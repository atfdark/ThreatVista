import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Send,
  X,
  Sparkles,
  ShieldAlert,
  Terminal,
  HelpCircle,
  Zap,
  CheckCircle,
  ArrowRight,
  RefreshCw,
  Cpu
} from 'lucide-react';
import { api } from '../services/mockData';

export default function ThreatCopilotDrawer({ isOpen, onClose, selectedEmployee = null }) {
  const [messages, setMessages] = useState([
    {
      id: 1,
      sender: 'copilot',
      text: `Hello Analyst! I am **ThreatVista AI Copilot**.\n\nI can analyze live endpoint telemetry, explain anomalous risk scores, map MITRE ATT&CK techniques, or execute forensic queries.`,
      suggestedActions: [
        'Why is this risk score high?',
        'Show active MITRE ATT&CK techniques',
        'Recommend containment playbook',
        'How does AES-256 Vault protect files?'
      ]
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  useEffect(() => {
    if (selectedEmployee) {
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
          sender: 'copilot',
          text: `🔍 **Active Context Loaded:** Analyzing **${selectedEmployee.name}** (${selectedEmployee.department} — ${selectedEmployee.role_type}). Current Risk Score: **${selectedEmployee.risk_score || 0}%**.\n\nAsk me why their score escalated or what actions to take.`,
          suggestedActions: [
            `Explain risk score for ${selectedEmployee.name}`,
            `Show MITRE techniques for ${selectedEmployee.name}`,
            `Generate containment steps`
          ]
        }
      ]);
    }
  }, [selectedEmployee]);

  const handleSend = async (customText = null) => {
    const textToSend = customText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg = {
      id: Date.now(),
      sender: 'user',
      text: textToSend
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!customText) setInput('');
    setLoading(true);

    try {
      const res = await api.copilotChat(textToSend, selectedEmployee?.id);
      const copilotMsg = {
        id: Date.now() + 1,
        sender: 'copilot',
        text: res.reply || 'Analysis completed.',
        suggestedActions: res.suggested_actions || []
      };
      setMessages((prev) => [...prev, copilotMsg]);
    } catch (err) {
      const errorMsg = {
        id: Date.now() + 1,
        sender: 'copilot',
        text: `⚠️ **AI Engine Notice:** Unable to contact reasoning backend (${err.message || err}). Falling back to local heuristic response.`,
        suggestedActions: ['Try again', 'Show high risk employees']
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-cyber-card/95 border-l border-cyber-border backdrop-blur-xl flex flex-col shadow-[0_0_50px_rgba(6,182,212,0.3)] animate-in slide-in-from-right duration-300">
      {/* Header */}
      <div className="p-4 border-b border-cyber-border flex items-center justify-between bg-cyber-bg/80">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-cyber-primary/20 border border-cyber-primary/40 flex items-center justify-center text-cyber-primary shadow-cyber">
            <Bot className="h-5 w-5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-cyber-text tracking-wide flex items-center gap-1.5">
              ThreatVista AI Copilot
              <span className="h-2 w-2 rounded-full bg-cyber-success shadow-[0_0_8px_#10b981]"></span>
            </h3>
            <p className="text-[11px] text-cyber-muted font-mono">
              Explainable Cybersecurity Assistant &amp; SOC Advisor
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-cyber-muted hover:text-cyber-text p-1.5 rounded-lg hover:bg-cyber-border/40 transition-colors"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Messages Stream */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs font-sans">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`max-w-[90%] p-3.5 rounded-xl border leading-relaxed ${
                msg.sender === 'user'
                  ? 'bg-cyber-primary/20 text-cyber-text border-cyber-primary/40 rounded-br-none shadow-cyber'
                  : 'bg-cyber-bg/90 text-cyber-text border-cyber-border rounded-bl-none shadow-sm'
              }`}
            >
              {/* Message text with basic markdown formatting */}
              <div className="space-y-2 whitespace-pre-wrap">
                {msg.text.split('\n\n').map((para, pIdx) => (
                  <p key={pIdx}>
                    {para.split('\n').map((line, lIdx) => (
                      <React.Fragment key={lIdx}>
                        {line}
                        {lIdx < para.split('\n').length - 1 && <br />}
                      </React.Fragment>
                    ))}
                  </p>
                ))}
              </div>
            </div>

            {/* Quick Action Suggestion Chips */}
            {msg.suggestedActions && msg.suggestedActions.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5 max-w-[90%]">
                {msg.suggestedActions.map((action, aIdx) => (
                  <button
                    key={aIdx}
                    onClick={() => handleSend(action)}
                    className="px-2.5 py-1 rounded-full bg-cyber-card border border-cyber-border hover:border-cyber-primary/60 text-cyber-muted hover:text-cyber-primary transition-all text-[11px] flex items-center gap-1 font-mono shadow-sm"
                  >
                    <Sparkles className="h-3 w-3 text-cyber-primary" />
                    <span>{action}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-cyber-primary bg-cyber-bg/60 p-3 rounded-lg border border-cyber-border max-w-[60%]">
            <RefreshCw className="h-4 w-4 animate-spin" />
            <span className="text-[11px] font-mono">Synthesizing telemetry &amp; MITRE matrix...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Field */}
      <div className="p-3 border-t border-cyber-border bg-cyber-bg/90">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Copilot (e.g. 'Why is risk 95%?' or 'Show USB activity')..."
            className="flex-1 bg-cyber-card border border-cyber-border rounded-lg px-3.5 py-2.5 text-xs text-cyber-text placeholder:text-cyber-muted focus:outline-none focus:border-cyber-primary/60"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="h-9 w-9 rounded-lg bg-cyber-primary text-cyber-bg font-bold flex items-center justify-center disabled:opacity-40 disabled:cursor-not-allowed hover:bg-cyber-primary/90 transition-all shadow-cyber"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
