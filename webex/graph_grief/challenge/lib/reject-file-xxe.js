module.exports = function rejectFileXxe(req, res, next) {
  if (!req.is('application/xml')) return next();

  const raw = req.body && req.body.toString && req.body.toString('utf8');
  if (!raw) return next();

  const rules = [
    {
      name: 'Character reference obfuscation in DOCTYPE',
      regex: /<!DOCTYPE[^>]*\[[\s\S]*?&#\d+;[\s\S]*?\]/i,
      log: ip => `[SECURITY] Blocked character reference obfuscation in DOCTYPE from ${ip}`,
      response: {
        status: 400,
        body: { error: 'Character references in DOCTYPE are not allowed' },
      },
    },
    {
      name: 'PUBLIC entity',
      regex: /<!ENTITY\s+[^>]*\bPUBLIC\b/i,
      log: ip => `[SECURITY] Blocked PUBLIC entity attempt from ${ip}`,
      response: {
        status: 400,
        body: { error: 'PUBLIC entities are not allowed' },
      },
    },
    {
      name: 'General SYSTEM entity',
      regex: /<!ENTITY\s+(?!%)[^>]*\bSYSTEM\b/i,
      log: ip => `[SECURITY] Blocked General SYSTEM entity attempt from ${ip}`,
      response: {
        status: 400,
        body: { error: 'General SYSTEM entities are not allowed' },
      },
    },
    {
      name: 'Localhost SYSTEM entity',
      regex: /<!ENTITY\s+[^>]*\bSYSTEM\s+["']https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|0:0:0:0:0:0:0:1)/i,
      log: ip => `[SECURITY] Blocked localhost SYSTEM entity attempt from ${ip}`,
      response: {
        status: 400,
        body: { error: 'Localhost access via SYSTEM entity is not allowed' },
      },
    },
    {
      name: 'Non-http(s) SYSTEM entity',
      regex: /<!ENTITY\s+[^>]*\bSYSTEM\s+["'](?!https?:\/\/)/i,
      log: ip => `[SECURITY] Blocked local/non-http SYSTEM entity attempt from ${ip}`,
      response: {
        status: 400,
        body: { error: 'Local or non-http(s) SYSTEM entities are not allowed' },
      },
    },
  ];

  for (const rule of rules) {
    if (rule.regex.test(raw)) {
      console.warn(rule.log(req.ip));
      return res.status(rule.response.status).json(rule.response.body);
    }
  }

  next();
};
