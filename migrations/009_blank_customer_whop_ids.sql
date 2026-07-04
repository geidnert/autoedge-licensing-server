UPDATE customers
SET whop_user_id = NULL
WHERE whop_user_id IS NOT NULL
  AND trim(whop_user_id) = '';

UPDATE customers
SET whop_member_id = NULL
WHERE whop_member_id IS NOT NULL
  AND trim(whop_member_id) = '';
