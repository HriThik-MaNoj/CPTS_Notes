import React from 'react';
import type { Phase } from '../data';

interface SidebarProps {
  phases: Phase[];
  activePhaseId: string;
  onPhaseSelect: (id: string) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ phases, activePhaseId, onPhaseSelect }) => {
  return (
    <nav className="sidebar">
      <div className="sidebar-header">
        <h1>AD PLAYBOOK</h1>
        <p>Methodology Reference</p>
      </div>
      <ul className="phase-list">
        {phases.map((phase, index) => (
          <React.Fragment key={phase.id}>
            {phase.id === 'A' && <li className="sidebar-separator">Appendices</li>}
            {phase.id === 'Z' && <li className="sidebar-separator">Final</li>}
            <li>
              <button
                className={`phase-link ${activePhaseId === phase.id ? 'active' : ''}`}
                onClick={() => onPhaseSelect(phase.id)}
              >
                <span className="phase-num">{phase.id}</span>
                <span className="phase-title">{phase.title.replace(/PHASE \d+ — |Appendix \w — /g, '')}</span>
              </button>
            </li>
          </React.Fragment>
        ))}
      </ul>
      <style>{`
        .sidebar {
          width: 300px;
          height: 100vh;
          background: var(--bg-card);
          border-right: 1px solid var(--border);
          position: fixed;
          left: 0;
          top: 0;
          overflow-y: auto;
          padding: 2rem 0;
        }
        .sidebar-header {
          padding: 0 2rem 2rem;
          border-bottom: 1px solid var(--border);
          margin-bottom: 1rem;
        }
        .sidebar-header h1 {
          font-size: 1.5rem;
          color: var(--accent);
          letter-spacing: 0.1em;
        }
        .sidebar-header p {
          font-size: 0.8rem;
          color: var(--text-secondary);
        }
        .sidebar-separator {
          padding: 1.5rem 2rem 0.5rem;
          font-size: 0.7rem;
          font-weight: 700;
          color: var(--accent);
          text-transform: uppercase;
          letter-spacing: 0.2em;
          opacity: 0.7;
        }
        .phase-list {
          list-style: none;
        }
        .phase-link {
          width: 100%;
          display: flex;
          align-items: center;
          gap: 1rem;
          padding: 0.8rem 2rem;
          background: transparent;
          border: none;
          color: var(--text-secondary);
          text-align: left;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 0.9rem;
        }
        .phase-link:hover {
          background: rgba(14, 165, 233, 0.05);
          color: var(--text-primary);
        }
        .phase-link.active {
          background: rgba(14, 165, 233, 0.1);
          color: var(--accent);
          border-right: 2px solid var(--accent);
        }
        .phase-num {
          font-family: var(--font-mono);
          opacity: 0.5;
        }
        .phase-title {
          font-weight: 500;
        }
      `}</style>
    </nav>
  );
};

export default Sidebar;
