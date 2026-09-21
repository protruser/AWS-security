import React, { useState } from "react"

interface LoginUser {
  username: string
  role: string
  team: string
}

export function LoginPage({
  onLogin,
}: {
  onLogin: (username: string, password: string) => Promise<LoginUser>
}) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password) {
      setError("아이디와 비밀번호를 입력해 주세요.")
      return
    }

    setLoading(true)
    setError("")
    try {
      await onLogin(username.trim(), password)
    } catch (err) {
      setError(err instanceof Error ? err.message : "로그인에 실패했습니다.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen bg-[#F6F7F9] flex items-center justify-center px-4"
      style={{
        fontFamily:
          "'Pretendard Variable', 'Pretendard', -apple-system, sans-serif",
      }}
    >
      <div className="w-full max-w-[390px] bg-white rounded-2xl border border-[#E4E7EC] shadow-sm p-7">
        <div className="flex items-center gap-3 mb-7">
          <div className="w-10 h-10 bg-[#111111] rounded-xl flex items-center justify-center flex-shrink-0">
            <svg
              viewBox="0 0 24 24"
              width="20"
              height="20"
              fill="none"
              stroke="white"
              strokeWidth="2.2"
            >
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
            </svg>
          </div>
          <div>
            <p className="text-[15px] font-bold text-[#111111]">
              AWS Security Monitoring Center
            </p>
            <p className="text-[11px] text-[#667085] mt-0.5">
              통합 보안관제 관리자 로그인
            </p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-[11px] font-semibold text-[#344054] mb-1.5">
              아이디
            </label>
            <input
              autoFocus
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full h-10 rounded-lg border border-[#D0D5DD] px-3 text-[12px] text-[#101828] outline-none focus:border-[#101828] focus:ring-2 focus:ring-[#101828]/10"
              placeholder="관리자 아이디"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-[#344054] mb-1.5">
              비밀번호
            </label>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full h-10 rounded-lg border border-[#D0D5DD] px-3 text-[12px] text-[#101828] outline-none focus:border-[#101828] focus:ring-2 focus:ring-[#101828]/10"
              placeholder="비밀번호"
            />
          </div>

          {error && (
            <div className="rounded-lg bg-[#FEF3F2] border border-[#FECDCA] px-3 py-2 text-[11px] text-[#B42318]">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full h-10 rounded-lg bg-[#111111] text-white text-[12px] font-bold hover:bg-[#262626] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? "로그인 중..." : "로그인"}
          </button>
        </form>

        <p className="text-[10px] text-[#98A2B3] mt-5 text-center">
          관리자 계정 정보는 Flask 서버의 .env에서 설정합니다.
        </p>
      </div>
    </div>
  )
}
