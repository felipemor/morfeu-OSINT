'use client';
import { useState, useMemo } from 'react';
import {
  Plus, Trash2, Edit3, Check, X, Calendar, ChevronLeft, ChevronRight,
  Clock, Flag, AlertCircle, CheckCircle2, Circle, Loader2
} from 'lucide-react';

export interface GanttTask {
  id: string;
  phase: string;
  name: string;
  start_date: string; // YYYY-MM-DD
  end_date: string;   // YYYY-MM-DD
  status: 'PLANNED' | 'IN_PROGRESS' | 'COMPLETED' | 'BLOCKED';
  assignee?: string;
  notes?: string;
  color?: string;
}

const PHASE_COLORS: Record<string, string> = {
  'Reconhecimento & OSINT': '#06b6d4',
  'Enumeração': '#8b5cf6',
  'Scanning Ativo': '#f59e0b',
  'Exploração': '#ef4444',
  'Pós-Exploração': '#f97316',
  'Relatório & Evidências': '#22c55e',
  'Custom': '#64748b',
};

const DEFAULT_PHASES = Object.keys(PHASE_COLORS);

const STATUS_ICONS: Record<string, React.ReactNode> = {
  PLANNED: <Circle className="w-3.5 h-3.5 text-slate-400" />,
  IN_PROGRESS: <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />,
  COMPLETED: <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />,
  BLOCKED: <AlertCircle className="w-3.5 h-3.5 text-red-400" />,
};

const STATUS_LABELS: Record<string, string> = {
  PLANNED: 'Planejado',
  IN_PROGRESS: 'Em Andamento',
  COMPLETED: 'Concluído',
  BLOCKED: 'Bloqueado',
};

interface GanttChartProps {
  tasks: GanttTask[];
  projectStart?: string;
  projectEnd?: string;
  onTasksChange?: (tasks: GanttTask[]) => void;
  readOnly?: boolean;
}

function parseDate(str: string): Date {
  const [y, m, d] = str.split('-').map(Number);
  return new Date(y, m - 1, d);
}

function formatDate(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function addDays(date: Date, days: number): Date {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

function diffDays(a: Date, b: Date): number {
  return Math.round((b.getTime() - a.getTime()) / (1000 * 60 * 60 * 24));
}

export default function GanttChart({
  tasks,
  projectStart,
  projectEnd,
  onTasksChange,
  readOnly = false,
}: GanttChartProps) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  // Determine chart range
  const chartStart = useMemo(() => {
    if (projectStart) return parseDate(projectStart);
    if (tasks.length > 0) {
      const dates = tasks.map(t => parseDate(t.start_date));
      const min = new Date(Math.min(...dates.map(d => d.getTime())));
      // round back to Monday
      const day = min.getDay();
      min.setDate(min.getDate() - (day === 0 ? 6 : day - 1));
      return min;
    }
    const d = new Date(today);
    d.setDate(d.getDate() - d.getDay() + 1);
    return d;
  }, [tasks, projectStart, today]);

  const chartEnd = useMemo(() => {
    if (projectEnd) return parseDate(projectEnd);
    if (tasks.length > 0) {
      const dates = tasks.map(t => parseDate(t.end_date));
      const max = new Date(Math.max(...dates.map(d => d.getTime())));
      max.setDate(max.getDate() + 7);
      return max;
    }
    return addDays(chartStart, 28);
  }, [tasks, projectEnd, chartStart]);

  const totalDays = Math.max(diffDays(chartStart, chartEnd), 14);

  // Build week columns
  const weeks = useMemo(() => {
    const w: { label: string; start: Date; days: number }[] = [];
    let cur = new Date(chartStart);
    while (cur < chartEnd) {
      const weekEnd = addDays(cur, 6);
      const daysInRange = Math.min(diffDays(cur, chartEnd), 7);
      w.push({
        label: `${cur.getDate()}/${cur.getMonth() + 1}`,
        start: new Date(cur),
        days: daysInRange,
      });
      cur = addDays(cur, 7);
    }
    return w;
  }, [chartStart, chartEnd]);

  // Today indicator position
  const todayPct = useMemo(() => {
    const d = diffDays(chartStart, today);
    if (d < 0 || d > totalDays) return null;
    return (d / totalDays) * 100;
  }, [chartStart, today, totalDays]);

  // Edit state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<GanttTask>>({});
  const [isAdding, setIsAdding] = useState(false);
  const [newTask, setNewTask] = useState<Partial<GanttTask>>({
    phase: DEFAULT_PHASES[0],
    status: 'PLANNED',
    start_date: formatDate(today),
    end_date: formatDate(addDays(today, 6)),
  });

  function startEdit(task: GanttTask) {
    setEditingId(task.id);
    setEditForm({ ...task });
  }

  function saveEdit() {
    if (!editingId || !onTasksChange) return;
    onTasksChange(tasks.map(t => t.id === editingId ? { ...t, ...editForm } as GanttTask : t));
    setEditingId(null);
    setEditForm({});
  }

  function deleteTask(id: string) {
    if (!onTasksChange) return;
    onTasksChange(tasks.filter(t => t.id !== id));
  }

  function addTask() {
    if (!onTasksChange || !newTask.name || !newTask.start_date || !newTask.end_date) return;
    const task: GanttTask = {
      id: `task-${Date.now()}`,
      phase: newTask.phase || DEFAULT_PHASES[0],
      name: newTask.name || '',
      start_date: newTask.start_date!,
      end_date: newTask.end_date!,
      status: newTask.status || 'PLANNED',
      notes: newTask.notes,
    };
    onTasksChange([...tasks, task]);
    setIsAdding(false);
    setNewTask({
      phase: DEFAULT_PHASES[0],
      status: 'PLANNED',
      start_date: formatDate(today),
      end_date: formatDate(addDays(today, 6)),
    });
  }

  function getTaskBarStyle(task: GanttTask) {
    const start = parseDate(task.start_date);
    const end = parseDate(task.end_date);
    const left = Math.max(0, (diffDays(chartStart, start) / totalDays) * 100);
    const width = Math.max(0.5, (diffDays(start, end) / totalDays) * 100);
    const color = PHASE_COLORS[task.phase] || PHASE_COLORS['Custom'];
    return { left: `${left}%`, width: `${width}%`, color };
  }

  const phaseGroups = useMemo(() => {
    const groups: Record<string, GanttTask[]> = {};
    tasks.forEach(t => {
      if (!groups[t.phase]) groups[t.phase] = [];
      groups[t.phase].push(t);
    });
    return groups;
  }, [tasks]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Calendar className="w-5 h-5 text-accent-cyan" />
          <span className="text-sm font-semibold text-slate-300">
            {formatDate(chartStart)} → {formatDate(chartEnd)}
            <span className="ml-2 text-slate-500 font-normal">({totalDays} dias)</span>
          </span>
        </div>
        {!readOnly && (
          <button
            onClick={() => setIsAdding(true)}
            className="btn-primary px-3 py-1.5 text-xs"
          >
            <Plus className="w-3.5 h-3.5" /> Nova Tarefa
          </button>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {Object.entries(PHASE_COLORS).slice(0, 6).map(([phase, color]) => (
          <div key={phase} className="flex items-center gap-1.5">
            <span className="w-3 h-2 rounded-sm" style={{ background: color }} />
            <span className="text-xs text-slate-400">{phase}</span>
          </div>
        ))}
      </div>

      {/* Gantt Grid */}
      <div className="glass-card overflow-hidden">
        {/* Timeline Header */}
        <div className="flex border-b border-bg-border">
          <div className="w-64 flex-shrink-0 px-4 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider border-r border-bg-border">
            Tarefa / Fase
          </div>
          <div className="flex-1 flex overflow-hidden">
            {weeks.map((week, i) => (
              <div
                key={i}
                className="text-xs text-slate-500 py-2 px-1 border-r border-bg-border/50 text-center"
                style={{ width: `${(week.days / totalDays) * 100}%`, flexShrink: 0 }}
              >
                {week.label}
              </div>
            ))}
          </div>
        </div>

        {/* Rows */}
        {tasks.length === 0 ? (
          <div className="py-12 text-center text-slate-500">
            <Calendar className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Nenhuma tarefa no cronograma</p>
            {!readOnly && (
              <button onClick={() => setIsAdding(true)} className="mt-3 text-xs text-accent-cyan hover:underline">
                + Adicionar primeira tarefa
              </button>
            )}
          </div>
        ) : (
          Object.entries(phaseGroups).map(([phase, phaseTasks]) => (
            <div key={phase}>
              {/* Phase header row */}
              <div className="flex bg-bg-primary/40 border-b border-bg-border/30">
                <div className="w-64 flex-shrink-0 px-4 py-1.5 flex items-center gap-2 border-r border-bg-border">
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ background: PHASE_COLORS[phase] || PHASE_COLORS['Custom'] }}
                  />
                  <span className="text-xs font-bold text-slate-300 truncate">{phase}</span>
                  <span className="text-xs text-slate-600 ml-auto">{phaseTasks.length}</span>
                </div>
                <div className="flex-1 relative">
                  {todayPct !== null && (
                    <div
                      className="absolute top-0 bottom-0 w-px bg-red-500/20"
                      style={{ left: `${todayPct}%` }}
                    />
                  )}
                </div>
              </div>

              {/* Task rows */}
              {phaseTasks.map((task) => {
                const { left, width, color } = getTaskBarStyle(task);
                const isEditing = editingId === task.id;

                return (
                  <div key={task.id} className="flex border-b border-bg-border/20 hover:bg-white/[0.01] group">
                    {/* Task name col */}
                    <div className="w-64 flex-shrink-0 px-4 py-2.5 border-r border-bg-border flex items-center gap-2 min-w-0">
                      <span className="flex-shrink-0">{STATUS_ICONS[task.status]}</span>
                      {isEditing ? (
                        <input
                          className="input-field text-xs py-0.5 flex-1 min-w-0"
                          value={editForm.name || ''}
                          onChange={e => setEditForm(f => ({ ...f, name: e.target.value }))}
                          autoFocus
                        />
                      ) : (
                        <span className="text-xs text-slate-300 truncate">{task.name}</span>
                      )}
                      {!readOnly && !isEditing && (
                        <div className="flex gap-1 ml-auto opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                          <button onClick={() => startEdit(task)} className="p-0.5 text-slate-500 hover:text-cyan-400">
                            <Edit3 className="w-3 h-3" />
                          </button>
                          <button onClick={() => deleteTask(task.id)} className="p-0.5 text-slate-500 hover:text-red-400">
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      )}
                      {isEditing && (
                        <div className="flex gap-1 ml-auto flex-shrink-0">
                          <button onClick={saveEdit} className="p-0.5 text-green-400 hover:text-green-300">
                            <Check className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => setEditingId(null)} className="p-0.5 text-slate-500 hover:text-red-400">
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Bar col */}
                    <div className="flex-1 relative py-2" style={{ minHeight: '40px' }}>
                      {/* Today line */}
                      {todayPct !== null && (
                        <div
                          className="absolute top-0 bottom-0 w-px bg-red-500/40 z-10"
                          style={{ left: `${todayPct}%` }}
                        />
                      )}
                      {/* Week grid lines */}
                      {weeks.map((week, wi) => (
                        <div
                          key={wi}
                          className="absolute top-0 bottom-0 border-r border-bg-border/20"
                          style={{ left: `${((diffDays(chartStart, week.start) + week.days) / totalDays) * 100}%` }}
                        />
                      ))}

                      {/* Task bar */}
                      <div
                        className="absolute top-1/2 -translate-y-1/2 rounded-md flex items-center px-2 cursor-default"
                        style={{
                          left,
                          width,
                          height: '20px',
                          background: `${color}33`,
                          border: `1px solid ${color}66`,
                          boxShadow: task.status === 'IN_PROGRESS' ? `0 0 8px ${color}44` : 'none',
                        }}
                        title={`${task.name}\n${task.start_date} → ${task.end_date}`}
                      >
                        <span
                          className="text-[10px] font-medium truncate"
                          style={{ color }}
                        >
                          {task.name}
                        </span>
                        {task.status === 'COMPLETED' && (
                          <div
                            className="absolute inset-0 rounded-md opacity-40"
                            style={{ background: `${color}66` }}
                          />
                        )}
                      </div>
                    </div>

                    {/* Status + dates right col */}
                    {isEditing && (
                      <div className="flex items-center gap-2 px-2 flex-shrink-0">
                        <input
                          type="date"
                          className="input-field text-xs py-0.5 w-32"
                          value={editForm.start_date || ''}
                          onChange={e => setEditForm(f => ({ ...f, start_date: e.target.value }))}
                        />
                        <input
                          type="date"
                          className="input-field text-xs py-0.5 w-32"
                          value={editForm.end_date || ''}
                          onChange={e => setEditForm(f => ({ ...f, end_date: e.target.value }))}
                        />
                        <select
                          className="input-field text-xs py-0.5 w-32"
                          value={editForm.status || 'PLANNED'}
                          onChange={e => setEditForm(f => ({ ...f, status: e.target.value as GanttTask['status'] }))}
                        >
                          {Object.entries(STATUS_LABELS).map(([v, l]) => (
                            <option key={v} value={v}>{l}</option>
                          ))}
                        </select>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ))
        )}

        {/* Today indicator label */}
        {todayPct !== null && tasks.length > 0 && (
          <div className="flex border-t border-bg-border/20">
            <div className="w-64 flex-shrink-0 border-r border-bg-border" />
            <div className="flex-1 relative h-5">
              <div
                className="absolute top-0 flex flex-col items-center"
                style={{ left: `${todayPct}%`, transform: 'translateX(-50%)' }}
              >
                <div className="w-px h-3 bg-red-500" />
                <span className="text-[9px] text-red-400 font-bold whitespace-nowrap">HOJE</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add Task Form */}
      {isAdding && (
        <div className="glass-card p-4 space-y-3 border border-accent-cyan/20">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Plus className="w-4 h-4 text-accent-cyan" />
              Nova Tarefa no Cronograma
            </h4>
            <button onClick={() => setIsAdding(false)} className="text-slate-500 hover:text-red-400">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="text-xs text-slate-400 mb-1 block">Nome da Tarefa *</label>
              <input
                className="input-field"
                placeholder="ex: Reconhecimento de Subdomínios"
                value={newTask.name || ''}
                onChange={e => setNewTask(t => ({ ...t, name: e.target.value }))}
              />
            </div>

            <div>
              <label className="text-xs text-slate-400 mb-1 block">Fase</label>
              <select
                className="input-field"
                value={newTask.phase || DEFAULT_PHASES[0]}
                onChange={e => setNewTask(t => ({ ...t, phase: e.target.value }))}
              >
                {DEFAULT_PHASES.map(p => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400 mb-1 block">Status</label>
              <select
                className="input-field"
                value={newTask.status || 'PLANNED'}
                onChange={e => setNewTask(t => ({ ...t, status: e.target.value as GanttTask['status'] }))}
              >
                {Object.entries(STATUS_LABELS).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400 mb-1 block">Data de Início *</label>
              <input
                type="date"
                className="input-field"
                value={newTask.start_date || ''}
                onChange={e => setNewTask(t => ({ ...t, start_date: e.target.value }))}
              />
            </div>

            <div>
              <label className="text-xs text-slate-400 mb-1 block">Data de Término *</label>
              <input
                type="date"
                className="input-field"
                value={newTask.end_date || ''}
                onChange={e => setNewTask(t => ({ ...t, end_date: e.target.value }))}
              />
            </div>

            <div className="col-span-2">
              <label className="text-xs text-slate-400 mb-1 block">Observações (opcional)</label>
              <input
                className="input-field"
                placeholder="Detalhes sobre esta tarefa..."
                value={newTask.notes || ''}
                onChange={e => setNewTask(t => ({ ...t, notes: e.target.value }))}
              />
            </div>
          </div>

          <div className="flex gap-2 pt-1">
            <button
              onClick={addTask}
              disabled={!newTask.name}
              className="btn-primary text-xs px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Check className="w-3.5 h-3.5" />
              Adicionar Tarefa
            </button>
            <button onClick={() => setIsAdding(false)} className="btn-ghost text-xs px-4 py-2">
              Cancelar
            </button>
          </div>
        </div>
      )}

      {/* Status Summary */}
      {tasks.length > 0 && (
        <div className="flex gap-4 flex-wrap">
          {Object.entries(STATUS_LABELS).map(([status, label]) => {
            const count = tasks.filter(t => t.status === status).length;
            if (count === 0) return null;
            return (
              <div key={status} className="flex items-center gap-1.5 text-xs">
                {STATUS_ICONS[status]}
                <span className="text-slate-400">{label}:</span>
                <span className="font-semibold text-slate-200">{count}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
