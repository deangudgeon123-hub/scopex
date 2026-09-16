-- Tighten the development operator RPC surface: only the anonymous web client needs these calls.
-- Signed-in customer sessions must never inherit access to the operator-only path.
revoke execute on function public.request_operator_scan(text,text) from authenticated;
revoke execute on function public.get_operator_scan_status(uuid,text) from authenticated;
