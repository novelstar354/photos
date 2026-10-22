-- Stacord: 管理者が指定したパスワードにリセット
-- Supabase SQL Editorで TARGET_USER_ID と NEW_PASSWORD を書き換えてから実行してください。
-- 注意: パスワードは平文でDBに保存しません。bcryptハッシュとして保存します。
-- 実行すると対象アカウントの既存セッションを削除します。

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

DO $$
DECLARE
  v_target_user_id text := 'TARGET_USER_ID'; -- 対象ユーザーのStacord ID
  v_new_password text := 'NEW_PASSWORD';     -- 自分で決める新しいパスワード
  v_account_id uuid;
BEGIN
  IF v_target_user_id = 'TARGET_USER_ID' OR length(trim(v_target_user_id)) = 0 THEN
    RAISE EXCEPTION 'v_target_user_id を対象ユーザーの user_id に変更してください';
  END IF;

  IF v_new_password = 'NEW_PASSWORD' OR length(v_new_password) < 8 THEN
    RAISE EXCEPTION 'v_new_password を8文字以上の新しいパスワードに変更してください';
  END IF;

  SELECT id
    INTO v_account_id
    FROM public.stacord_accounts
   WHERE user_id = v_target_user_id
   LIMIT 1;

  IF v_account_id IS NULL THEN
    RAISE EXCEPTION 'Stacord account not found for user_id: %', v_target_user_id;
  END IF;

  -- bcryptはSupabaseのpgcrypto cryptで生成。bcryptjsのbcrypt.compareと互換性があります。
  UPDATE public.stacord_accounts
     SET password_hash = extensions.crypt(v_new_password, extensions.gen_salt('bf', 12)),
         updated_at = now()
   WHERE id = v_account_id;

  -- 既存ログインセッションを無効化
  DELETE FROM public.stacord_sessions
   WHERE account_id = v_account_id;
END
$$;

COMMIT;

-- 更新後の確認（パスワードやハッシュは表示しません）
SELECT user_id, display_name, updated_at
FROM public.stacord_accounts
WHERE user_id = 'TARGET_USER_ID';
