function createRateLimiter({ maxRequests, windowMs }) {
  const requests = new Map();

  return (req, res, next) => {
    const now = Date.now();
    const key = req.socket.remoteAddress || 'unknown';
    const record = requests.get(key);

    if (!record || now - record.startedAt >= windowMs) {
      requests.set(key, { startedAt: now, count: 1 });
      return next();
    }

    record.count += 1;
    if (record.count > maxRequests) {
      const retryAfter = Math.ceil((windowMs - (now - record.startedAt)) / 1000);
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many requests. Try again later.'
        }
      });
    }
    next();
  };
}

module.exports = { createRateLimiter };
