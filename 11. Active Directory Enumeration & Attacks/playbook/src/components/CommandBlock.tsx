import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CommandBlockProps {
  label: string;
  cmd: string;
  description?: string;
}

const CommandBlock: React.FC<CommandBlockProps> = ({ label, cmd, description }) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="command-block">
      <div className="command-header">
        <span className="command-label">{label}</span>
        <button onClick={copyToClipboard} className="copy-btn">
          {copied ? <Check size={14} /> : <Copy size={14} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="command-text">
        <code>{cmd}</code>
      </pre>
      {description && <p className="command-desc">{description}</p>}
      <style>{`
        .command-block {
          background: var(--terminal-bg);
          border: 1px solid var(--border);
          border-radius: 6px;
          margin: 1rem 0;
          overflow: hidden;
          transition: border-color 0.2s;
        }
        .command-block:hover {
          border-color: var(--accent);
        }
        .command-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0.5rem 1rem;
          background: rgba(255, 255, 255, 0.05);
          border-bottom: 1px solid var(--border);
        }
        .command-label {
          font-size: 0.8rem;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .copy-btn {
          display: flex;
          align-items: center;
          gap: 0.4rem;
          background: transparent;
          border: none;
          color: var(--text-secondary);
          cursor: pointer;
          font-size: 0.75rem;
          padding: 0.2rem 0.5rem;
          border-radius: 4px;
          transition: background 0.2s, color 0.2s;
        }
        .copy-btn:hover {
          background: rgba(255, 255, 255, 0.1);
          color: var(--accent);
        }
        .command-text {
          padding: 1rem;
          overflow-x: auto;
          color: #a5f3fc;
          font-size: 0.9rem;
        }
        .command-desc {
          padding: 0.5rem 1rem 1rem;
          font-size: 0.85rem;
          color: var(--text-secondary);
          border-top: 1px solid rgba(255, 255, 255, 0.05);
        }
      `}</style>
    </div>
  );
};

export default CommandBlock;
