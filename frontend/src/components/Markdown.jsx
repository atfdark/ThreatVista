import React from 'react';

/**
 * Lightweight, dependency-free markdown renderer for ARGUS replies.
 * Supports: headings, paragraphs, bold/italic, inline code, fenced code,
 * ordered/unordered lists, tables, blockquotes and horizontal rules.
 */

const renderInline = (text, keyPrefix = 'i') => {
  if (!text) return null;
  const tokens = [];
  // order matters: code first, then bold, then italic
  const regex = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*\s][^*]*\*)|(_[^_\s][^_]*_)/g;
  let last = 0;
  let m;
  let idx = 0;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) tokens.push(text.slice(last, m.index));
    const tok = m[0];
    const k = `${keyPrefix}-${idx++}`;
    if (tok.startsWith('`')) {
      tokens.push(
        <code key={k} className="px-1.5 py-0.5 rounded-md bg-cyber-primary/10 border border-cyber-primary/20 text-cyber-primary font-mono text-[0.85em] break-all">
          {tok.slice(1, -1)}
        </code>
      );
    } else if (tok.startsWith('**')) {
      tokens.push(<strong key={k} className="font-semibold text-white">{renderInline(tok.slice(2, -2), k)}</strong>);
    } else {
      tokens.push(<em key={k} className="italic text-slate-300">{tok.slice(1, -1)}</em>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) tokens.push(text.slice(last));
  return tokens;
};

const splitRow = (line) =>
  line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());

export default function Markdown({ text }) {
  if (!text) return null;
  const lines = text.replace(/\r/g, '').split('\n');
  const blocks = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) { i++; continue; }

    // Fenced code
    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim();
      const buf = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) { buf.push(lines[i]); i++; }
      i++;
      blocks.push(
        <div key={key++} className="rounded-lg border border-cyber-border bg-black/40 overflow-hidden">
          {lang && <div className="px-3 py-1 text-[10px] uppercase tracking-wider text-cyber-muted border-b border-cyber-border font-mono">{lang}</div>}
          <pre className="p-3 overflow-x-auto text-[11px] font-mono text-emerald-300 leading-relaxed">{buf.join('\n')}</pre>
        </div>
      );
      continue;
    }

    // Headings
    const h = trimmed.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      const cls = level <= 2
        ? 'text-[15px] font-bold text-white mt-1'
        : level === 3
          ? 'text-[14px] font-bold text-white flex items-center gap-1.5 pb-1.5 border-b border-cyber-border/60'
          : 'text-[12.5px] font-semibold text-cyber-primary mt-2 uppercase tracking-wide';
      blocks.push(<div key={key++} className={cls}>{renderInline(h[2], `h${key}`)}</div>);
      i++;
      continue;
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,})$/.test(trimmed)) {
      blocks.push(<hr key={key++} className="border-cyber-border/60" />);
      i++;
      continue;
    }

    // Table
    if (trimmed.startsWith('|') && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      const header = splitRow(trimmed);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) { rows.push(splitRow(lines[i])); i++; }
      blocks.push(
        <div key={key++} className="overflow-x-auto rounded-lg border border-cyber-border/80 bg-black/20">
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr className="bg-cyber-primary/10">
                {header.map((c, ci) => (
                  <th key={ci} className="text-left px-2.5 py-1.5 font-semibold text-cyber-primary whitespace-nowrap border-b border-cyber-border">
                    {renderInline(c, `th${key}-${ci}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri} className="border-b border-cyber-border/40 last:border-0 hover:bg-cyber-primary/5 transition-colors">
                  {r.map((c, ci) => (
                    <td key={ci} className="px-2.5 py-1.5 align-top text-slate-300">{renderInline(c, `td${key}-${ri}-${ci}`)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    // Blockquote
    if (trimmed.startsWith('>')) {
      const buf = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) { buf.push(lines[i].trim().replace(/^>\s?/, '')); i++; }
      blocks.push(
        <blockquote key={key++} className="border-l-2 border-cyber-warning/70 bg-cyber-warning/5 pl-3 pr-2 py-2 rounded-r-md text-slate-300">
          {renderInline(buf.join(' '), `bq${key}`)}
        </blockquote>
      );
      continue;
    }

    // Lists
    if (/^([-*•]|\d+\.)\s+/.test(trimmed)) {
      const ordered = /^\d+\./.test(trimmed);
      const items = [];
      while (i < lines.length && /^([-*•]|\d+\.)\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^([-*•]|\d+\.)\s+/, ''));
        i++;
      }
      const ListTag = ordered ? 'ol' : 'ul';
      blocks.push(
        <ListTag key={key++} className={`space-y-1 pl-5 ${ordered ? 'list-decimal marker:text-cyber-primary marker:font-semibold' : 'list-disc marker:text-cyber-primary'}`}>
          {items.map((it, ii) => <li key={ii} className="text-slate-200 pl-0.5">{renderInline(it, `li${key}-${ii}`)}</li>)}
        </ListTag>
      );
      continue;
    }

    // Paragraph (merge consecutive plain lines)
    const buf = [];
    while (
      i < lines.length && lines[i].trim() &&
      !/^(#{1,4}\s|```|\||>|([-*•]|\d+\.)\s)/.test(lines[i].trim())
    ) { buf.push(lines[i].trim()); i++; }
    blocks.push(
      <p key={key++} className="text-slate-200">
        {buf.map((b, bi) => (
          <React.Fragment key={bi}>{renderInline(b, `p${key}-${bi}`)}{bi < buf.length - 1 && <br />}</React.Fragment>
        ))}
      </p>
    );
  }

  return <div className="space-y-2.5 leading-relaxed">{blocks}</div>;
}
