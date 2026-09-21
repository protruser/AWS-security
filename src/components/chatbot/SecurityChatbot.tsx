import { useEffect, useRef, useState } from "react"
import { SUGGESTED_QUESTIONS } from "../../data/mock"
import type { ActionEvent } from "../../data/types"
import { SeverityBadge } from "../shared/common"

interface ChatMessage {
  role: "user" | "bot"

  text: string

  actions?: string[]
}

export function SecurityChatbot({
  selectedEvent,
  onHighlightPath,
  onShowRecommend,
}: {
  selectedEvent: ActionEvent | null

  onHighlightPath: () => void

  onShowRecommend: () => void
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([])

  const [input, setInput] = useState("")
  const [sending, setSending] = useState(false)

  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current)
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages, sending])

  const sendMessage = async (text: string) => {
    const trimmed = text.trim()
    if (!trimmed || sending) return

    const history = messages.map((message) => ({
      role: message.role,
      text: message.text,
    }))

    setMessages((prev) => [...prev, { role: "user", text: trimmed }])
    setInput("")
    setSending(true)

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          message: trimmed,
          history,
          event: selectedEvent,
        }),
      })

      const data = (await response.json()) as {
        text?: string
        actions?: string[]
        message?: string
      }

      if (!response.ok) {
        throw new Error(data.message || `Chat API ${response.status}`)
      }

      setMessages((prev) => [
        ...prev,
        {
          role: "bot",
          text: data.text || "응답을 받지 못했습니다.",
          actions: data.actions || [],
        },
      ])
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          role: "bot",
          text: `챗봇 연결 오류: ${
            error instanceof Error ? error.message : "알 수 없는 오류"
          }`,
        },
      ])
    } finally {
      setSending(false)
    }
  }

  const handleActionBtn = (action: string) => {
    if (action === "공격 경로 강조") onHighlightPath()

    if (action === "권장 조치 보기") onShowRecommend()
  }

  const handleClear = () => setMessages([])

  return (
    <div className="flex flex-col h-full bg-white">
      {/* Chatbot header */}
      <div className="flex items-center gap-2 px-3 py-2.5 border-b border-[#E0E0E0] flex-shrink-0 bg-[#FAFAFA]">
        <div className="w-6 h-6 rounded-lg bg-[#111111] flex items-center justify-center flex-shrink-0">
          <svg
            viewBox="0 0 24 24"
            width="13"
            height="13"
            fill="none"
            stroke="white"
            strokeWidth="2.2"
          >
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[11px] font-bold text-[#0D0D0D] leading-tight">
            보안 분석 어시스턴트
          </p>
          <div className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A]" />
            <span className="text-[9px] text-[#6B6B6B]">온라인</span>
          </div>
        </div>
        <button
          onClick={handleClear}
          className="text-[10px] text-[#6B6B6B] hover:text-[#0D0D0D] px-1.5 py-1 rounded border border-[#E0E0E0] hover:bg-white transition-colors"
        >
          새 대화
        </button>
      </div>

      {/* Context chip */}
      {selectedEvent && (
        <div className="px-3 py-1.5 bg-[#F5F5F5] border-b border-[#D4D4D4] flex-shrink-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[9px] font-bold text-[#111111]">
              컨텍스트:
            </span>
            <span className="text-[9px] bg-white border border-[#A3A3A3] text-[#111111] px-1.5 py-0.5 rounded-full font-medium">
              {selectedEvent.title}
            </span>
            <SeverityBadge sev={selectedEvent.severity} small />
            <span className="text-[9px] text-[#111111]">
              {selectedEvent.service}
            </span>
          </div>
        </div>
      )}

      {/* Message area */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.length === 0 && (
          <div className="text-center py-3">
            <p className="text-[10px] text-[#6B6B6B] leading-relaxed mb-3">
              탐지된 이벤트, 원본 로그 또는 권장 조치에 대해 질문해 보세요.
            </p>
            <div className="grid grid-cols-2 gap-1.5">
              {SUGGESTED_QUESTIONS.map((q) => (
                <button
                  key={q}
                  onClick={() => void sendMessage(q)}
                  className="text-[10px] text-[#111111] bg-[#F5F5F5] hover:bg-[#E0E0E0] border border-[#D4D4D4] px-2 py-1.5 rounded-lg text-left transition-colors leading-tight"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}
        {sending && (
          <div className="flex justify-start">
            <div className="bg-[#F5F5F5] text-[#667085] rounded-2xl rounded-tl-sm px-3 py-2">
              <p className="text-[11px]">분석 중...</p>
            </div>
          </div>
        )}
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${
              msg.role === "user" ? "justify-end" : "justify-start"
            }`}
          >
            <div
              className={`max-w-[90%] ${
                msg.role === "user"
                  ? "bg-[#111111] text-white rounded-2xl rounded-tr-sm px-3 py-2"
                  : "bg-[#F5F5F5] text-[#0D0D0D] rounded-2xl rounded-tl-sm px-3 py-2"
              }`}
            >
              <p className="text-[11px] leading-relaxed">{msg.text}</p>
              {msg.actions && msg.actions.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {msg.actions.map((a) => (
                    <button
                      key={a}
                      onClick={() => handleActionBtn(a)}
                      className="text-[9px] font-medium bg-white text-[#111111] border border-[#D4D4D4] px-1.5 py-0.5 rounded-full hover:bg-[#F5F5F5] transition-colors"
                    >
                      {a}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Input area */}
      <div className="border-t border-[#E0E0E0] p-2.5 flex-shrink-0 bg-[#FAFAFA]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.nativeEvent.isComposing) {
                void sendMessage(input)
              }
            }}
            disabled={sending}
            placeholder="보안 이벤트 또는 로그에 대해 질문하세요"
            className="flex-1 text-[11px] border border-[#E0E0E0] rounded-lg px-2.5 py-1.5 outline-none focus:border-[#111111] bg-white disabled:bg-[#F2F4F7]"
          />
          <button
            onClick={() => void sendMessage(input)}
            disabled={sending}
            className="text-[11px] font-bold text-white bg-[#111111] hover:bg-[#262626] px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {sending ? "분석 중" : "전송"}
          </button>
        </div>
      </div>
    </div>
  )
}
