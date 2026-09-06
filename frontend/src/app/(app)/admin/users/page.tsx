'use client';

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi, usersApi, UserAccount } from '@/lib/api';
import {
  Users, UserPlus, ShieldCheck, ShieldAlert, Lock, Trash2,
  CheckCircle2, RefreshCw, AlertCircle, Key, UserCheck, UserX, Crown
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function UserManagementPage() {
  const queryClient = useQueryClient();
  const currentUser = authApi.getUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newRole, setNewRole] = useState<UserAccount['role']>('PENTESTER');

  const { data: users = [], isLoading, refetch } = useQuery({
    queryKey: ['users_list'],
    queryFn: usersApi.list,
    enabled: isAdmin,
  });

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail || !newEmail.includes('@')) {
      toast.error('Informe um endereço de e-mail corporativo válido.');
      return;
    }
    if (!newFullName.trim()) {
      toast.error('Informe o nome completo do operador.');
      return;
    }

    try {
      toast.loading('Criando novo acesso de usuário...', { id: 'create-user' });
      await usersApi.create({
        email: newEmail.trim(),
        full_name: newFullName.trim(),
        role: newRole,
      });
      toast.success(`Usuário ${newEmail} cadastrado com sucesso!`, { id: 'create-user' });
      setIsModalOpen(false);
      setNewEmail('');
      setNewFullName('');
      setNewRole('PENTESTER');
      queryClient.invalidateQueries({ queryKey: ['users_list'] });
    } catch (err: any) {
      toast.error(err.message || 'Erro ao criar usuário', { id: 'create-user' });
    }
  };

  const handleRevokeUser = async (userId: string, email: string) => {
    if (userId === currentUser?.id) {
      toast.error('Você não pode revogar seu próprio acesso de Administrador.');
      return;
    }
    try {
      toast.loading(`Revogando acesso de ${email}...`, { id: 'revoke-user' });
      await usersApi.revoke(userId);
      toast.success(`Acesso de ${email} suspenso com sucesso.`, { id: 'revoke-user' });
      queryClient.invalidateQueries({ queryKey: ['users_list'] });
    } catch (err: any) {
      toast.error(err.message || 'Erro ao revogar acesso', { id: 'revoke-user' });
    }
  };

  if (!isAdmin) {
    return (
      <div className="p-8 max-w-4xl mx-auto text-center space-y-4">
        <div className="inline-flex p-4 rounded-2xl bg-red-950/40 border border-red-500/40 text-red-400">
          <ShieldAlert className="w-12 h-12" />
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Acesso Restrito: 403 Forbidden</h1>
        <p className="text-sm text-slate-400 max-w-md mx-auto">
          Somente o **Administrador Master (`ADMIN`)** possui autorização para visualizar, criar e gerenciar acessos de usuários na plataforma.
        </p>
        <div className="pt-2">
          <span className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 font-mono text-xs border border-slate-700">
            Seu perfil atual: {currentUser?.role || 'DESCONHECIDO'} ({currentUser?.email || 'Nenhum'})
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge-cyan text-xs font-semibold px-2 py-0.5 rounded uppercase tracking-wider">
              Gerenciamento Admin
            </span>
            <span className="text-xs text-slate-400">• Controle Centralizado de Identidades &amp; Perfis</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Crown className="w-6 h-6 text-amber-400" />
            Gerenciamento de Acessos &amp; Segregação de Usuários
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Crie, atribua papéis e gerencie permissões de operadores. Usuários comuns visualizam apenas os projetos de sua propriedade.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsModalOpen(true)}
            className="btn-primary px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg shadow-accent-cyan/20 cursor-pointer"
          >
            <UserPlus className="w-4 h-4" />
            Novo Usuário / Operador
          </button>
          <button onClick={() => refetch()} className="btn-ghost p-2 text-slate-400 hover:text-white" title="Atualizar">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 uppercase font-semibold">Total de Usuários</span>
            <p className="text-2xl font-bold text-slate-100 mt-1">{users.length}</p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-accent-cyan/15 flex items-center justify-center text-accent-cyan">
            <Users className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 uppercase font-semibold">Acessos Ativos</span>
            <p className="text-2xl font-bold text-emerald-400 mt-1">
              {users.filter(u => u.status === 'ACTIVE').length}
            </p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-500/15 flex items-center justify-center text-emerald-400">
            <UserCheck className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 uppercase font-semibold">Perfis Administradores</span>
            <p className="text-2xl font-bold text-amber-400 mt-1">
              {users.filter(u => u.role === 'ADMIN').length}
            </p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-amber-500/15 flex items-center justify-center text-amber-400">
            <Crown className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="glass-card overflow-hidden">
        <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Users className="w-4 h-4 text-accent-cyan" />
            Tabela de Identidades &amp; Permissões de Acesso
          </h2>
          <span className="text-xs text-slate-400 font-mono">Total: {users.length} usuários</span>
        </div>

        <div className="overflow-x-auto">
          <table className="table-dark w-full">
            <thead>
              <tr>
                <th>Operador / E-mail</th>
                <th>Nome Completo</th>
                <th>Papel (Role)</th>
                <th>Status do Acesso</th>
                <th>Data de Cadastro</th>
                <th className="text-right">Ações</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-slate-200">
                        {user.full_name.charAt(0)}
                      </div>
                      <div>
                        <p className="font-mono text-xs text-slate-100 font-bold">{user.email}</p>
                        <span className="text-[10px] text-slate-500 font-mono">{user.id}</span>
                      </div>
                    </div>
                  </td>
                  <td className="text-slate-300 text-xs font-semibold">{user.full_name}</td>
                  <td>
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase font-mono border ${
                      user.role === 'ADMIN'
                        ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                        : user.role === 'PENTESTER'
                        ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                        : 'bg-purple-500/15 text-purple-300 border-purple-500/30'
                    }`}>
                      {user.role}
                    </span>
                  </td>
                  <td>
                    {user.status === 'ACTIVE' ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="w-3 h-3" /> ATIVO
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30">
                        <UserX className="w-3 h-3" /> SUSPENSO
                      </span>
                    )}
                  </td>
                  <td className="text-slate-400 text-xs font-mono">
                    {new Date(user.created_at).toLocaleDateString('pt-BR')}
                  </td>
                  <td className="text-right">
                    {user.id !== currentUser?.id && user.status === 'ACTIVE' && (
                      <button
                        onClick={() => handleRevokeUser(user.id, user.email)}
                        className="px-2.5 py-1 text-xs font-bold bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg transition-all"
                        title="Suspender acesso"
                      >
                        Suspender
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Novo Usuário */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-md bg-bg-card border border-bg-border rounded-2xl p-6 space-y-5 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <UserPlus className="w-5 h-5 text-accent-cyan" />
                Cadastrar Novo Acesso (Admin Only)
              </h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Nome Completo do Operador
                </label>
                <input
                  type="text"
                  value={newFullName}
                  onChange={(e) => setNewFullName(e.target.value)}
                  placeholder="ex: João Silva"
                  required
                  className="w-full px-3.5 py-2 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-100 focus:border-accent-cyan focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  E-mail Corporativo
                </label>
                <input
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="ex: joao.silva@empresa.com"
                  required
                  className="w-full px-3.5 py-2 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-100 focus:border-accent-cyan focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Papel no Sistema (Role &amp; Permissões)
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as any)}
                  className="w-full px-3.5 py-2 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-100 focus:border-accent-cyan focus:outline-none"
                >
                  <option value="PENTESTER">PENTESTER (Acesso restrito aos seus próprios projetos)</option>
                  <option value="ANALYST">ANALYST (Leitura e triagem de vulnerabilidades)</option>
                  <option value="AUDITOR">AUDITOR (Visualização de relatórios e laudos)</option>
                  <option value="ADMIN">ADMIN (Controle total de usuários e projetos)</option>
                </select>
              </div>

              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 space-y-1">
                <p className="font-bold flex items-center gap-1">
                  <Lock className="w-3.5 h-3.5" /> Política de Segregação:
                </p>
                <p className="text-[11px] text-amber-200/80">
                  Usuários criados como `PENTESTER` ou `ANALYST` enxergarão apenas as aplicações em que forem definidos como proprietários (`owner_id`).
                </p>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="btn-primary px-5 py-2 rounded-xl text-xs font-bold"
                >
                  Cadastrar Usuário
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
