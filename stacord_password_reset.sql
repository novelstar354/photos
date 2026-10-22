-- Stacord: 管理者が指定したユーザーのパスワードをリセットする
-- Supabase SQL Editor で、TARGET_USER_ID を対象ユーザーの user_id に置き換えて実行してください。
-- 生成された仮パスワードは最後の SELECT 結果に一度表示されます。安全な場所に控えてください。
-- 現在の実装（bcryptjs hash(..., 12) / bcrypt.compare(...)）と互換の bcrypt ハッシュを保存します。

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

CREATE TEMP TABLE IF NOT EXISTS stacord_password_reset_result (
  user_id text,
  temporary_password text
) ON COMMIT DROP;

TRUNCATE TABLE stacord_password_reset_result;

DO $$
DECLARE
  v_target_user_id text := 'TARGET_USER_ID'; -- ←ここを書き換える
  v_account_id uuid;
  v_password text;
BEGIN
  SELECT id
    INTO v_account_id
    FROM public.stacord_accounts
   WHERE user_id = v_target_user_id
   LIMIT 1;

  IF v_account_id IS NULL THEN
    RAISE EXCEPTION 'Stacord account not found for user_id: %', v_target_user_id;
  END IF;

  -- 18 random bytes encoded as hex: 36-character temporary password
  v_password := encode(extensions.gen_random_bytes(18), 'hex');

  UPDATE public.stacord_accounts
     SET password_hash = extensions.crypt(v_password, extensions.gen_salt('bf', 12)),
         updated_at = now()
   WHERE id = v_account_id;

  -- Revoke every active session for this account.
  DELETE FROM public.stacord_sessions
   WHERE account_id = v_account_id;

  INSERT INTO stacord_password_reset_result(user_id, temporary_password)
  VALUES (v_target_user_id, v_password);
END
$$;

-- Copy the temporary password from this result. It is not stored in a permanent table.
SELECT user_id, temporary_password
FROM stacord_password_reset_result;

COMMIT;
