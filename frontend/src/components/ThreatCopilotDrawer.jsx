import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Send,
  X,
  Sparkles,
  RefreshCw,
  Copy,
  Check,
  UserCheck
} from 'lucide-react';
import { api } from '../services/mockData';
import Markdown from './Markdown';

export default function ThreatCopilotDrawer({ isOpen, onClose, selectedEmployee = null }) {
  const initialGreeting = {
    id: 1,
    sender: 'copilot',
    text: `### 👁️ Hello Analyst! I am **ARGUS**.\n\nI am ThreatVista's **explainable AI security copilot**. You can ask me anything about:\n\n- **Employees & Risk:** *"Tell me about Vaidehi"*, *"Is there any problem with her?"*, *"Why is her risk 100%?"*\n- **Forensic Activity:** *"Show all USB activity in Finance after 8 PM"*, *"Did anyone delete files today?"*\n- **Comparisons:** *"Compare Vaidehi and kamaal"*\n- **Incidents & Playbooks:** *"Analyze latest incident"*, *"What is the containment playbook?"*\n- **Concepts & Architecture:** *"How does Shadow Vault AES-256 protect files?"*, *"What is zero trust?"*`,
    suggestedActions: [
      'Give me a security overview',
      'Show high-risk employees',
      'Analyze latest incident',
      'How does AES-256 Vault protect files?'
    ]
  };

  const [messages, setMessages] = useState([initialGreeting]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [focusEmployee, setFocusEmployee] = useState(selectedEmployee);
  const [copiedId, setCopiedId] = useState(null);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  useEffect(() => {
    if (selectedEmployee) {
      setFocusEmployee(selectedEmployee);
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
          sender: 'copilot',
          text: `🔍 **Active Context Loaded:** Focusing on **${selectedEmployee.name}** (${selectedEmployee.department} — ${selectedEmployee.role_type || 'General'}). Current Risk Score: **${selectedEmployee.risk_score || 0}%**.\n\nAsk me what they did, whether there is any problem, or what actions to take.`,
          suggestedActions: [
            `What did ${selectedEmployee.name.split(' ')[0]} do?`,
            `Is there any problem with ${selectedEmployee.name.split(' ')[0]}?`,
            `Why is ${selectedEmployee.name.split(' ')[0]}'s risk score high?`,
            `Show ${selectedEmployee.name.split(' ')[0]}'s USB activity`
          ]
        }
      ]);
    }
  }, [selectedEmployee]);

  const handleCopy = (id, text) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const handleClear = () => {
    setMessages([initialGreeting]);
    setFocusEmployee(selectedEmployee || null);
  };

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
      // Build conversation history for context grounding
      const history = messages
        .filter((m) => m.sender === 'user' || m.sender === 'copilot')
        .map((m) => ({
          role: m.sender === 'user' ? 'user' : 'assistant',
          text: m.text
        }))
        .slice(-10);

      const targetEmpId = focusEmployee?.id || selectedEmployee?.id || null;

      const res = await api.copilotChat(textToSend, targetEmpId, {
        history,
        focus_employee: focusEmployee
      });

      if (res?.focus_employee) {
        setFocusEmployee(res.focus_employee);
      }

      const copilotMsg = {
        id: Date.now() + 1,
        sender: 'copilot',
        text: res.reply || 'Analysis completed.',
        suggestedActions: res.suggested_actions || [],
        engine: res.engine || 'argus'
      };
      setMessages((prev) => [...prev, copilotMsg]);
    } catch (err) {
      const errorMsg = {
        id: Date.now() + 1,
        sender: 'copilot',
        text: `⚠️ **AI Engine Notice:** Unable to contact reasoning backend (${err.message || err}). Falling back to local heuristic response.`,
        suggestedActions: ['Give me a security overview', 'Show high-risk employees']
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl lg:max-w-2xl bg-cyber-card/95 border-l border-cyber-border backdrop-blur-2xl flex flex-col shadow-[0_0_60px_rgba(6,182,212,0.25)] animate-in slide-in-from-right duration-300">
      {/* Header */}
      <div className="p-4 border-b border-cyber-border flex items-center justify-between bg-cyber-bg/90">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyber-primary/20 to-cyber-secondary/20 border border-cyber-primary/40 flex items-center justify-center text-cyber-primary shadow-cyber relative overflow-hidden">
            <Bot className="h-5 w-5 relative z-10" />
            {loading && <div className="absolute inset-0 bg-cyber-primary/30 animate-pulse" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-cyber-text tracking-wide flex items-center gap-1.5 font-mono">
                ARGUS
                <span className="h-2 w-2 rounded-full bg-cyber-success shadow-[0_0_8px_#10b981]" />
              </h3>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary">
                AI Copilot
              </span>
            </div>
            <p className="text-[11px] text-cyber-muted font-mono">
              Explainable Cybersecurity Assistant & SOC Intelligence
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={handleClear}
            title="Reset conversation"
            className="text-cyber-muted hover:text-cyber-text p-1.5 rounded-lg hover:bg-cyber-border/40 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <button
            onClick={onClose}
            title="Close drawer"
            className="text-cyber-muted hover:text-cyber-text p-1.5 rounded-lg hover:bg-cyber-border/40 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Focus employee indicator bar */}
      {focusEmployee && (
        <div className="px-4 py-2 bg-cyber-primary/5 border-b border-cyber-border flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-1.5 text-cyber-primary font-mono">
            <UserCheck className="h-3.5 w-3.5" />
            <span>Target Context: <strong>{focusEmployee.name}</strong></span>
            {focusEmployee.department && <span className="text-cyber-muted">({focusEmployee.department})</span>}
          </div>
          <button
            onClick={() => setFocusEmployee(null)}
            className="text-cyber-muted hover:text-cyber-danger text-[10px] font-mono underline"
          >
            clear context
          </button>
        </div>
      )}

      {/* Messages Stream */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs font-sans">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`group relative max-w-[95%] p-4 rounded-xl border leading-relaxed ${
                msg.sender === 'user'
                  ? 'bg-cyber-primary/15 text-cyber-text border-cyber-primary/40 rounded-br-none shadow-cyber'
                  : 'bg-cyber-bg/95 text-cyber-text border-cyber-border rounded-bl-none shadow-md'
              }`}
            >
              {msg.sender === 'copilot' ? (
                <div className="relative">
                  <Markdown text={msg.text} />
                  <div className="mt-2.5 pt-2 border-t border-cyber-border/40 flex items-center justify-between text-[10px] text-cyber-muted font-mono">
                    <span>ARGUS Engine</span>
                    <button
                      onClick={() => handleCopy(msg.id, msg.text)}
                      className="inline-flex items-center gap-1 hover:text-cyber-primary transition-colors"
                    >
                      {copiedId === msg.id ? (
                        <>
                          <Check className="h-3 w-3 text-cyber-success" />
                          <span className="text-cyber-success">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="whitespace-pre-wrap font-sans text-slate-100">
                  {msg.text}
                </div>
              )}
            </div>

            {/* Quick Action Suggestion Chips */}
            {msg.suggestedActions && msg.suggestedActions.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5 max-w-[95%] animate-in fade-in slide-in-from-bottom-2 duration-300">
                {msg.suggestedActions.map((action, aIdx) => (
                  <button
                    key={aIdx}
                    onClick={() => handleSend(action)}
                    className="px-2.5 py-1 rounded-full bg-cyber-card/90 border border-cyber-border hover:border-cyber-primary/60 text-slate-300 hover:text-cyber-primary transition-all text-[11px] flex items-center gap-1 font-mono shadow-sm hover:scale-[1.02]"
                  >
                    <Sparkles className="h-3 w-3 text-cyber-primary" />
                    <span>{action}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}

        {/* Thinking Indicator */}
        {loading && (
          <div className="flex items-start gap-2 max-w-[70%]">
            <div className="p-3.5 rounded-xl bg-cyber-bg/95 text-cyber-text border border-cyber-border rounded-bl-none shadow-sm flex items-center gap-2.5">
              <div className="flex space-x-1">
                <div className="w-1.5 h-1.5 bg-cyber-primary rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-1.5 h-1.5 bg-cyber-primary rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-1.5 h-1.5 bg-cyber-primary rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
              <span className="text-[11px] font-mono text-cyber-primary animate-pulse">
                ARGUS is analyzing telemetry & baselines...
              </span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Field */}
      <div className="p-3 border-t border-cyber-border bg-cyber-bg/95">
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
            placeholder="Ask ARGUS about any employee, department, action, or risk..."
            className="flex-1 bg-cyber-card border border-cyber-border rounded-lg px-3.5 py-2.5 text-xs text-cyber-text placeholder:text-cyber-muted focus:outline-none focus:border-cyber-primary/60 transition-colors"
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
