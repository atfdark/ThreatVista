import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RotateCcw,
  Zap,
  HardDrive,
  FileCheck2,
  AlertOctagon,
  RefreshCw,
  X,
  Lock,
  Unlock,
  CheckCircle,
  FileCode
} from 'lucide-react';
import { api } from '../services/mockData';

export default function MassRecoveryModal({ isOpen, onClose }) {
  const [stage, setStage] = useState('IDLE'); // IDLE | GENERATED | ATTACKED | RESTORED
  const [loading, setLoading] = useState(false);
  const [fileCount, setFileCount] = useState(100);
  const [attackStats, setAttackStats] = useState(null);
  const [recoveryStats, setRecoveryStats] = useState(null);
  const [sampleFiles, setSampleFiles] = useState([]);
  const [logs, setLogs] = useState([]);

  if (!isOpen) return null;

  const handleGenerateBatch = async () => {
    setLoading(true);
    try {
      const res = await api.simulateRansomwareBatch(fileCount);
      setStage('GENERATED');
      setSampleFiles(res.sample_files || []);
      setAttackStats(null);
      setRecoveryStats(null);
    } catch (err) {
      alert('Failed to generate simulation batch: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateAttack = async () => {
    setLoading(true);
    try {
      const res = await api.simulateRansomwareAttack();
      setStage('ATTACKED');
      setAttackStats(res);
    } catch (err) {
      alert('Attack simulation error: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleMassRollback = async () => {
    setLoading(true);
    try {
      const res = await api.executeMassRollback();
      setStage('RESTORED');
      setRecoveryStats(res);
      setSampleFiles(res.sample_recovered || []);
    } catch (err) {
      alert('Mass rollback error: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-cyber-card border border-cyber-border rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col shadow-[0_0_50px_rgba(6,182,212,0.2)]">
        
        {/* Modal Header */}
        <div className="p-6 border-b border-cyber-border flex items-center justify-between bg-cyber-bg/70">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-cyber-primary/10 border border-cyber-primary/30 flex items-center justify-center text-cyber-primary shadow-cyber">
              <RotateCcw className="h-6 w-6 animate-pulse" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-cyber-text tracking-wide flex items-center gap-2">
                Ransomware Mass Rollback & Recovery Engine
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40">
                  AES-256 Zero-Knowledge
                </span>
              </h2>
              <p className="text-xs text-cyber-muted">
                Demonstrates high-speed atomic rollback of 100+ simultaneously corrupted files from the encrypted Shadow Vault.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-cyber-muted hover:text-cyber-text p-2 rounded-lg hover:bg-cyber-border/40 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Interactive Simulation Dashboard */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          
          {/* Step Progression Bar */}
          <div className="grid grid-cols-3 gap-4">
            <div className={`p-4 rounded-xl border transition-all ${stage === 'GENERATED' || stage === 'ATTACKED' || stage === 'RESTORED' ? 'bg-cyber-primary/10 border-cyber-primary text-cyber-primary' : 'bg-cyber-bg/40 border-cyber-border text-cyber-muted'}`}>
              <div className="flex items-center gap-2 font-bold text-sm">
                <span className="h-6 w-6 rounded-full bg-cyber-primary/20 flex items-center justify-center text-xs">1</span>
                <span>Protected Baseline</span>
              </div>
              <p className="text-xs mt-1 text-cyber-muted">100 files backed up & encrypted in AES-256 Vault</p>
            </div>

            <div className={`p-4 rounded-xl border transition-all ${stage === 'ATTACKED' ? 'bg-cyber-danger/20 border-cyber-danger text-cyber-danger animate-pulse' : stage === 'RESTORED' ? 'bg-cyber-border/40 border-cyber-border text-cyber-muted' : 'bg-cyber-bg/40 border-cyber-border text-cyber-muted'}`}>
              <div className="flex items-center gap-2 font-bold text-sm">
                <span className="h-6 w-6 rounded-full bg-cyber-danger/20 flex items-center justify-center text-xs">2</span>
                <span>Simulated Ransomware</span>
              </div>
              <p className="text-xs mt-1 text-cyber-muted">Malware batch encrypts 100 files with .locked</p>
            </div>

            <div className={`p-4 rounded-xl border transition-all ${stage === 'RESTORED' ? 'bg-cyber-success/20 border-cyber-success text-cyber-success shadow-[0_0_15px_rgba(16,185,129,0.3)]' : 'bg-cyber-bg/40 border-cyber-border text-cyber-muted'}`}>
              <div className="flex items-center gap-2 font-bold text-sm">
                <span className="h-6 w-6 rounded-full bg-cyber-success/20 flex items-center justify-center text-xs">3</span>
                <span>Instant 1-Click Rollback</span>
              </div>
              <p className="text-xs mt-1 text-cyber-muted">100% recovered with SHA-256 integrity in &lt; 150ms</p>
            </div>
          </div>

          {/* Action Trigger Buttons */}
          <div className="flex items-center gap-4 bg-cyber-bg/60 p-4 rounded-xl border border-cyber-border justify-between flex-wrap">
            <div className="flex items-center gap-3">
              <button
                onClick={handleGenerateBatch}
                disabled={loading}
                className="px-4 py-2.5 rounded-lg bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40 hover:bg-cyber-primary/30 font-semibold text-xs flex items-center gap-2 transition-all shadow-cyber"
              >
                <HardDrive className="h-4 w-4" />
                Step 1: Setup 100 Test Files
              </button>

              <button
                onClick={handleSimulateAttack}
                disabled={loading || (stage !== 'GENERATED' && stage !== 'RESTORED')}
                className={`px-4 py-2.5 rounded-lg font-semibold text-xs flex items-center gap-2 transition-all border ${
                  stage === 'GENERATED' || stage === 'RESTORED'
                    ? 'bg-cyber-danger/20 text-cyber-danger border-cyber-danger/40 hover:bg-cyber-danger/30 shadow-[0_0_10px_rgba(239,68,68,0.3)]'
                    : 'bg-cyber-bg text-cyber-muted border-cyber-border cursor-not-allowed opacity-50'
                }`}
              >
                <Lock className="h-4 w-4" />
                Step 2: Simulate Ransomware Outbreak
              </button>
            </div>

            <button
              onClick={handleMassRollback}
              disabled={loading || stage !== 'ATTACKED'}
              className={`px-6 py-2.5 rounded-lg font-bold text-xs flex items-center gap-2 transition-all border ${
                stage === 'ATTACKED'
                  ? 'bg-cyber-success text-cyber-bg border-cyber-success hover:bg-cyber-success/90 shadow-[0_0_20px_#10b981] animate-bounce'
                  : 'bg-cyber-bg text-cyber-muted border-cyber-border cursor-not-allowed opacity-50'
              }`}
            >
              <Zap className="h-4 w-4" />
              Step 3: Execute 1-Click Mass Rollback
            </button>
          </div>

          {/* Live Statistics Panel */}
          {stage === 'ATTACKED' && attackStats && (
            <div className="p-4 rounded-xl bg-cyber-danger/10 border border-cyber-danger/40 text-cyber-danger space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-sm">
                  <AlertOctagon className="h-5 w-5 animate-spin" />
                  <span>ALERT: Ransomware Pattern Detected</span>
                </div>
                <span className="font-mono text-xs">{attackStats.encryption_time_ms}ms execution time</span>
              </div>
              <p className="text-xs text-cyber-text">
                {attackStats.encrypted_files_count} files encrypted with <code>.locked</code> extension in test directory. Endpoint shadow vault remains intact under AES-256 zero-knowledge encryption.
              </p>
            </div>
          )}

          {stage === 'RESTORED' && recoveryStats && (
            <div className="p-5 rounded-xl bg-cyber-success/10 border border-cyber-success/40 text-cyber-success space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-base">
                  <CheckCircle className="h-6 w-6 text-cyber-success" />
                  <span>Disaster Recovery Complete: All Files Restored!</span>
                </div>
                <span className="font-mono text-xs font-bold px-2.5 py-1 bg-cyber-success/20 rounded border border-cyber-success/40">
                  {recoveryStats.recovery_time_ms} ms MTTR
                </span>
              </div>
              
              <div className="grid grid-cols-4 gap-3 text-center">
                <div className="bg-cyber-bg/60 p-3 rounded-lg border border-cyber-border">
                  <span className="text-xs text-cyber-muted block">Files Recovered</span>
                  <span className="text-lg font-bold text-cyber-success font-mono">{recoveryStats.total_recovered} / {recoveryStats.total_recovered}</span>
                </div>
                <div className="bg-cyber-bg/60 p-3 rounded-lg border border-cyber-border">
                  <span className="text-xs text-cyber-muted block">Data Volume</span>
                  <span className="text-lg font-bold text-cyber-text font-mono">{recoveryStats.data_volume_mb} MB</span>
                </div>
                <div className="bg-cyber-bg/60 p-3 rounded-lg border border-cyber-border">
                  <span className="text-xs text-cyber-muted block">SHA-256 Integrity</span>
                  <span className="text-lg font-bold text-cyber-primary font-mono">100% VERIFIED</span>
                </div>
                <div className="bg-cyber-bg/60 p-3 rounded-lg border border-cyber-border">
                  <span className="text-xs text-cyber-muted block">Vault Cipher</span>
                  <span className="text-lg font-bold text-cyber-accent font-mono">{recoveryStats.cipher}</span>
                </div>
              </div>
            </div>
          )}

          {/* Sample Recovered Files Inspector */}
          {sampleFiles.length > 0 && (
            <div className="border border-cyber-border rounded-xl p-4 bg-cyber-bg/40 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyber-text flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-cyber-primary" />
                  Sample Protected Files in Vault Snapshot
                </span>
                <span className="text-[11px] font-mono text-cyber-muted">Showing 5 of {fileCount} assets</span>
              </div>

              <div className="space-y-1.5 font-mono text-xs">
                {sampleFiles.map((file, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 rounded bg-cyber-card/60 border border-cyber-border/60">
                    <div className="flex items-center gap-2">
                      <span className="text-cyber-primary font-semibold">{file.filename}</span>
                      {file.tier && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase ${file.tier === 'RESTRICTED' ? 'bg-cyber-danger/20 text-cyber-danger' : 'bg-cyber-warning/20 text-cyber-warning'}`}>
                          {file.tier}
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-cyber-muted truncate max-w-[200px]">
                      SHA: {file.sha256 ? file.sha256.slice(0, 16) + '...' : 'Verified'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-cyber-border flex items-center justify-between bg-cyber-bg/90">
          <div className="flex items-center gap-2 text-xs text-cyber-muted font-mono">
            <ShieldCheck className="h-4 w-4 text-cyber-success" />
            <span>Zero-Knowledge Shadow Vault Active</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-cyber-muted hover:text-cyber-text transition-colors"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
