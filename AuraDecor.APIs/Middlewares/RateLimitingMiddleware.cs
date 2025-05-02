using System.Net;
using System.Text.Json;
using AuraDecor.APIs.Errors;
using AuraDecor.APIs.Helpers;
using Microsoft.AspNetCore.Mvc.Controllers;
using StackExchange.Redis;

namespace AuraDecor.APIs.Middlewares;

public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<RateLimitingMiddleware> _logger;

    public RateLimitingMiddleware(
        RequestDelegate next,
        IConnectionMultiplexer redis,
        ILogger<RateLimitingMiddleware> logger)
    {
        _next = next;
        _redis = redis;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        if (endpoint == null)
        {
            await _next(context);
            return;
        }

        var controllerActionDescriptor = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>();
        if (controllerActionDescriptor == null)
        {
            await _next(context);
            return;
        }

        var rateLimit = endpoint.Metadata.GetMetadata<RateLimitAttribute>();
        if (rateLimit == null)
        {
            await _next(context);
            return;
        }

        var clientId = GetClientIdentifier(context);
        var resource = context.Request.Path;

        bool isAllowed;
        int remaining = 0;
        TimeSpan? resetTime = null;

        switch (rateLimit.Algorithm)
        {
            case RateLimitAlgorithm.SlidingWindow:
                (isAllowed, remaining, resetTime) = await CheckSlidingWindowLimitAsync(
                    clientId, resource, rateLimit.MaxRequests, rateLimit.TimeWindowInSeconds);
                break;
            case RateLimitAlgorithm.TokenBucket:
                (isAllowed, remaining, resetTime) = await CheckTokenBucketLimitAsync(
                    clientId, resource, rateLimit.MaxRequests, rateLimit.TimeWindowInSeconds);
                break;
            case RateLimitAlgorithm.FixedWindow:
            default:
                (isAllowed, remaining, resetTime) = await CheckFixedWindowLimitAsync(
                    clientId, resource, rateLimit.MaxRequests, rateLimit.TimeWindowInSeconds);
                break;
        }

        context.Response.OnStarting(() => {
            context.Response.Headers.Append("X-RateLimit-Limit", rateLimit.MaxRequests.ToString());
            context.Response.Headers.Append("X-RateLimit-Remaining", remaining.ToString());
            if (resetTime.HasValue)
            {
                context.Response.Headers.Append("X-RateLimit-Reset", 
                    ((DateTimeOffset)DateTime.UtcNow.Add(resetTime.Value)).ToUnixTimeSeconds().ToString());
            }
            return Task.CompletedTask;
        });

        if (!isAllowed)
        {
            _logger.LogWarning($"Rate limit exceeded for client {clientId} on {resource}");
            context.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
            context.Response.ContentType = "application/json";

            var response = new ApiResponse(429, "you're banned for being gay");
            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            var json = JsonSerializer.Serialize(response, options);

            await context.Response.WriteAsync(json);
            return;
        }

        await _next(context);
    }

    // ALGORITHM 1: FIXED WINDOW
    private async Task<(bool IsAllowed, int Remaining, TimeSpan? ResetTime)> CheckFixedWindowLimitAsync(
        string clientId, string resource, int limit, int windowSeconds)
    {
        var db = _redis.GetDatabase();
        var key = $"rate-limit:fixed:{clientId}:{resource}";
        
        var transaction = db.CreateTransaction();
        var counterTask = transaction.StringGetAsync(key);
        var ttlTask = transaction.KeyTimeToLiveAsync(key);
        
        await transaction.ExecuteAsync();
        
        var currentCount = await counterTask;
        var ttl = await ttlTask;
        
        var count = currentCount.IsNull ? 0 : int.Parse(currentCount.ToString());
        
        if (count >= limit)
        {
            return (false, 0, ttl);
        }
        
        // Use Lua script for atomic increment and expiry
        var script = @"
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current";
        
        await db.ScriptEvaluateAsync(script, new RedisKey[] { key }, new RedisValue[] { windowSeconds });
        
        return (true, limit - count - 1, ttl);
    }

    // ALGORITHM 2: SLIDING WINDOW
    private async Task<(bool IsAllowed, int Remaining, TimeSpan? ResetTime)> CheckSlidingWindowLimitAsync(
        string clientId, string resource, int limit, int windowSeconds)
    {
        var db = _redis.GetDatabase();
        var key = $"rate-limit:sliding:{clientId}:{resource}";
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var windowStart = now - (windowSeconds * 1000);
        
        var script = @"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local windowStart = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local windowSeconds = tonumber(ARGV[4])
            
            -- Remove expired entries
            redis.call('ZREMRANGEBYSCORE', key, 0, windowStart)
            
            -- Count requests in current window
            local requestCount = redis.call('ZCARD', key)
            
            -- Check if limit exceeded
            if requestCount >= limit then
                -- Get oldest timestamp to calculate reset time
                local oldestTimestamp = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
                if #oldestTimestamp > 0 then
                    return {0, 0, windowSeconds}
                else
                    return {0, 0, windowSeconds}
                end
            end
            
            -- Add current request
            redis.call('ZADD', key, now, now .. '-' .. redis.call('INCR', key .. ':id'))
            redis.call('EXPIRE', key, windowSeconds)
            
            -- Return remaining requests and TTL
            return {1, limit - requestCount - 1, redis.call('TTL', key)}";
        
        var result = (RedisResult[])(await db.ScriptEvaluateAsync(
            script,
            new RedisKey[] { key },
            new RedisValue[] { now.ToString(), windowStart.ToString(), limit.ToString(), windowSeconds.ToString() }
        ))!;
        
        // Safer conversions to avoid overflow issues
        bool isAllowed = result[0].ToString() == "1";
        int remaining;
        if (!int.TryParse(result[1].ToString(), out remaining))
        {
            remaining = 0;
        }
        
        TimeSpan? resetTime;
        int resetSeconds;
        if (int.TryParse(result[2].ToString(), out resetSeconds) && resetSeconds > 0)
        {
            resetTime = TimeSpan.FromSeconds(resetSeconds);
        }
        else
        {
            resetTime = TimeSpan.FromSeconds(windowSeconds); // Default fallback
        }
        
        return (isAllowed, remaining, resetTime);
    }

    // ALGORITHM 3: TOKEN BUCKET
    private async Task<(bool IsAllowed, int Remaining, TimeSpan? ResetTime)> CheckTokenBucketLimitAsync(
        string clientId, string resource, int limit, int windowSeconds)
    {
        var db = _redis.GetDatabase();
        var bucketKey = $"rate-limit:bucket:{clientId}:{resource}";
        var timestampKey = $"rate-limit:bucket-ts:{clientId}:{resource}";
        
        var refillRate = (double)limit / windowSeconds; // Tokens per second
        
        // Using Lua script for atomic token bucket operations
        var script = @"
            local bucketKey = KEYS[1]
            local timestampKey = KEYS[2]
            local now = tonumber(ARGV[1])
            local capacity = tonumber(ARGV[2])
            local refillRate = tonumber(ARGV[3])
            local windowSeconds = tonumber(ARGV[4])
            
            -- Get or initialize tokens and last updated time
            local tokens = tonumber(redis.call('GET', bucketKey) or capacity)
            local lastRefillTime = tonumber(redis.call('GET', timestampKey) or now)
            
            -- Calculate time elapsed since last refill
            local elapsedSeconds = now - lastRefillTime
            
            -- Refill tokens based on time elapsed
            tokens = math.min(capacity, tokens + (elapsedSeconds * refillRate))
            
            -- If no tokens available, return false
            if tokens < 1 then
                -- Calculate time until next token is available
                local timeToNextToken = (1 - tokens) / refillRate
                return {0, 0, math.ceil(timeToNextToken)}
            end
            
            -- Consume token and update values
            tokens = tokens - 1
            redis.call('SET', bucketKey, tokens, 'EX', windowSeconds)
            redis.call('SET', timestampKey, now, 'EX', windowSeconds)
            
            return {1, math.floor(tokens), windowSeconds}";
        
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        var result = (RedisResult[])await db.ScriptEvaluateAsync(
            script,
            new RedisKey[] { bucketKey, timestampKey },
            new RedisValue[] { now.ToString(), limit.ToString(), refillRate.ToString(), windowSeconds.ToString() }
        );
        
        // Safer conversions to avoid overflow issues
        bool isAllowed = result[0].ToString() == "1";
        int remaining;
        if (!int.TryParse(result[1].ToString(), out remaining))
        {
            remaining = 0;
        }
        
        TimeSpan? resetTime;
        int resetSeconds;
        if (int.TryParse(result[2].ToString(), out resetSeconds) && resetSeconds > 0)
        {
            resetTime = TimeSpan.FromSeconds(resetSeconds);
        }
        else
        {
            resetTime = TimeSpan.FromSeconds(windowSeconds); 
        }
        
        return (isAllowed, remaining, resetTime);
    }

    private string GetClientIdentifier(HttpContext context)
    {
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                return userId;
            }
        }
        
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}
