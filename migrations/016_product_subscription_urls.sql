ALTER TABLE products ADD COLUMN subscription_url TEXT;

UPDATE products
SET subscription_url = 'https://whop.com/auto-edge/duo-nasdaq-futures-bot/',
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE slug IN ('duo-runtime', 'duorc-runtime')
   OR feature_id IN ('strategy.duo.runtime', 'strategy.duorc.runtime');
