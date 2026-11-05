// Fail fast if production secrets are missing — prevents silent use of dev defaults
if (process.env.NODE_ENV === 'production') {
  const required = ['HANDSOFF_API_KEY', 'HANDSOFF_TOKEN_SECRET'];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length > 0) {
    console.error(`Missing required environment variables: ${missing.join(', ')}`);
    process.exit(1);
  }
}

const app = require('./src/app');

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Hands-Off API listening on port ${port}`);
});
