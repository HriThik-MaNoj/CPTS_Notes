import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import CommandBlock from './components/CommandBlock';
import { methodologyData } from './data';
import { Target, Flag, Shield, Activity } from 'lucide-react';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

function App() {
  const [activePhaseId, setActivePhaseId] = useState(methodologyData[0].id);

  const activePhase = methodologyData.find(p => p.id === activePhaseId) || methodologyData[0];

  return (
    <div className="app-container">
      <Sidebar 
        phases={methodologyData} 
        activePhaseId={activePhaseId} 
        onPhaseSelect={setActivePhaseId} 
      />
      
      <main className="content">
        <header className="content-header">
          <div className="phase-badge">Phase {activePhase.id}</div>
          <h1>{activePhase.title}</h1>
          <div className="goal-container">
            <Target size={20} className="goal-icon" />
            <p className="goal-text"><strong>Goal:</strong> {activePhase.goal}</p>
          </div>
        </header>

        <section className="phase-content">
          {activePhase.sections.map((section, idx) => (
            <div key={idx} className="section-card">
              <h2 className="section-title">{section.title}</h2>
              {section.content && (
                <div className="section-markdown">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {section.content}
                  </ReactMarkdown>
                </div>
              )}
              
              {section.commands && section.commands.length > 0 && (
                <div className="commands-list">
                  {section.commands.map((cmd, cmdIdx) => (
                    <CommandBlock 
                      key={cmdIdx}
                      label={cmd.label}
                      cmd={cmd.cmd}
                      description={cmd.description}
                    />
                  ))}
                </div>
              )}
            </div>
          ))}
        </section>

        <footer className="iteration-rule">
          <Activity size={24} />
          <div>
            <h3>Universal Iteration Rule</h3>
            <p>Every time you obtain a new credential, computer, or right, return to Phase 4 (re-enumerate as the new identity).</p>
          </div>
        </footer>
      </main>

      <style>{`
        .app-container {
          display: flex;
          min-height: 100vh;
        }
        .content {
          margin-left: 300px;
          flex: 1;
          padding: 4rem;
          max-width: 1000px;
        }
        .content-header {
          margin-bottom: 3rem;
        }
        .phase-badge {
          display: inline-block;
          background: rgba(14, 165, 233, 0.1);
          color: var(--accent);
          padding: 0.25rem 0.75rem;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 1rem;
          border: 1px solid rgba(14, 165, 233, 0.2);
        }
        .content-header h1 {
          font-size: 2.5rem;
          margin-bottom: 1.5rem;
          color: var(--text-primary);
        }
        .goal-container {
          display: flex;
          align-items: flex-start;
          gap: 1rem;
          background: rgba(255, 255, 255, 0.03);
          padding: 1.5rem;
          border-left: 4px solid var(--accent);
          border-radius: 0 8px 8px 0;
        }
        .goal-icon {
          color: var(--accent);
          flex-shrink: 0;
          margin-top: 0.2rem;
        }
        .goal-text {
          font-size: 1.1rem;
          color: var(--text-primary);
        }
        .section-card {
          margin-bottom: 3rem;
        }
        .section-title {
          font-size: 1.5rem;
          margin-bottom: 1rem;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.75rem;
        }
        .section-markdown {
          color: var(--text-secondary);
          margin-bottom: 1.5rem;
        }
        .section-markdown table {
          width: 100%;
          border-collapse: collapse;
          margin: 1.5rem 0;
          font-size: 0.9rem;
          background: rgba(255, 255, 255, 0.02);
          border-radius: 8px;
          overflow: hidden;
        }
        .section-markdown th, .section-markdown td {
          padding: 0.75rem 1rem;
          text-align: left;
          border-bottom: 1px solid var(--border);
        }
        .section-markdown th {
          background: rgba(255, 255, 255, 0.05);
          color: var(--accent);
          font-weight: 600;
          text-transform: uppercase;
          font-size: 0.8rem;
          letter-spacing: 0.05em;
        }
        .section-markdown tr:last-child td {
          border-bottom: none;
        }
        .section-markdown ul, .section-markdown ol {
          margin: 1rem 0 1.5rem 1.5rem;
        }
        .section-markdown li {
          margin-bottom: 0.5rem;
        }
        .section-markdown code {
          background: rgba(14, 165, 233, 0.1);
          color: var(--accent);
          padding: 0.2rem 0.4rem;
          border-radius: 4px;
          font-size: 0.85rem;
        }
        .section-markdown pre code {
          background: transparent;
          padding: 0;
        }
        .section-markdown pre {
          background: var(--terminal-bg);
          padding: 1rem;
          border-radius: 6px;
          border: 1px solid var(--border);
          margin: 1rem 0;
          overflow-x: auto;
        }
        .iteration-rule {
          margin-top: 5rem;
          background: linear-gradient(to right, rgba(14, 165, 233, 0.1), transparent);
          padding: 2rem;
          border-radius: 12px;
          border: 1px solid rgba(14, 165, 233, 0.2);
          display: flex;
          align-items: center;
          gap: 1.5rem;
          color: var(--accent);
        }
        .iteration-rule h3 {
          margin-bottom: 0.25rem;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          font-size: 0.9rem;
        }
        .iteration-rule p {
          color: var(--text-primary);
          font-size: 0.95rem;
        }

        @media (max-width: 1024px) {
          .sidebar {
            width: 80px;
          }
          .sidebar-header, .phase-title {
            display: none;
          }
          .phase-link {
            justify-content: center;
            padding: 1.5rem 0;
          }
          .content {
            margin-left: 80px;
            padding: 2rem;
          }
        }
      `}</style>
    </div>
  );
}

export default App;
