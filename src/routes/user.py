from flask import Blueprint, jsonify, request
from src.models.user import User, AdminPermission, db
from datetime import datetime, timedelta
import secrets
import string
import requests
import hashlib

user_bp = Blueprint('user', __name__)

# Configurações do webhook do Discord (substitua pela URL real)
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE"

def send_discord_log(message):
    """Envia log para o Discord via webhook"""
    try:
        payload = {
            "content": message,
            "username": "API Bot"
        }
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except:
        pass  # Falha silenciosa para não quebrar a API

def generate_random_username(length=5):
    """Gera um nome de usuário aleatório de 5 dígitos"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def verify_admin_permission(discord_user_id):
    """Verifica se o usuário do Discord tem permissão de administrador"""
    permission = AdminPermission.query.filter_by(discord_user_id=discord_user_id).first()
    return permission is not None

def verify_generation_permission(discord_user_id):
    """Verifica se o usuário do Discord tem permissão para gerar usuários"""
    permission = AdminPermission.query.filter_by(discord_user_id=discord_user_id).first()
    return permission is not None and permission.can_generate_users

# Rotas de autenticação
@user_bp.route('/auth/login', methods=['POST'])
def login():
    """Endpoint para login de usuários"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')
    
    if not username or not password:
        return jsonify({'error': 'Username e password são obrigatórios'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        send_discord_log(f"❌ Tentativa de login falhada: Usuário '{username}' não encontrado - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    if not user.check_password(password):
        send_discord_log(f"❌ Tentativa de login falhada: Senha incorreta para '{username}' - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({'error': 'Senha incorreta'}), 401
    
    if user.is_expired():
        send_discord_log(f"❌ Tentativa de login falhada: Usuário '{username}' expirado - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({'error': 'Usuário expirado'}), 403
    
    if user.is_paused:
        send_discord_log(f"❌ Tentativa de login falhada: Usuário '{username}' pausado - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        return jsonify({'error': 'Usuário pausado'}), 403
    
    # Verificar HWID
    if user.hwid is None:
        # Primeiro login - registrar HWID
        if hwid:
            user.hwid = hwid
            user.first_login = datetime.utcnow()
            # Iniciar contagem de expiração após primeiro login
            if user.expires_at and user.first_login:
                # Se a expiração foi definida em dias, calcular a partir do primeiro login
                pass
        else:
            return jsonify({'error': 'HWID é obrigatório no primeiro login'}), 400
    else:
        # Verificar se o HWID corresponde
        if hwid != user.hwid:
            send_discord_log(f"❌ Tentativa de login falhada: HWID incorreto para '{username}' - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
            return jsonify({'error': 'HWID não corresponde'}), 403
    
    user.is_logged_in = True
    db.session.commit()
    
    send_discord_log(f"✅ Login bem-sucedido: '{username}' - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return jsonify({
        'message': 'Login realizado com sucesso',
        'user': user.to_dict()
    }), 200

@user_bp.route('/auth/logout', methods=['POST'])
def logout():
    """Endpoint para logout de usuários"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username é obrigatório'}), 400
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_logged_in = False
        db.session.commit()
        return jsonify({'message': 'Logout realizado com sucesso'}), 200
    
    return jsonify({'error': 'Usuário não encontrado'}), 404

# Rotas administrativas
@user_bp.route('/admin/user/create', methods=['POST'])
def create_user():
    """Criar novo usuário (admin ou comum)"""
    data = request.json
    discord_user_id = data.get('discord_user_id')
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    expiration_days = data.get('expiration_days')
    expiration_hours = data.get('expiration_hours')
    
    # Verificar permissão
    if not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para criar usuários'}), 403
    
    if not username or not password:
        return jsonify({'error': 'Username e password são obrigatórios'}), 400
    
    # Verificar se usuário já existe
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Usuário já existe'}), 409
    
    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    
    # Definir expiração
    if expiration_days:
        user.expires_at = datetime.utcnow() + timedelta(days=int(expiration_days))
    elif expiration_hours:
        user.expires_at = datetime.utcnow() + timedelta(hours=int(expiration_hours))
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'Usuário criado com sucesso',
        'user': user.to_dict()
    }), 201

@user_bp.route('/admin/user/generate', methods=['POST'])
def generate_users():
    """Gerar usuários aleatórios"""
    data = request.json
    discord_user_id = data.get('discord_user_id')
    days = data.get('days', 30)
    quantity = data.get('quantity', 1)
    
    # Verificar permissão
    if not verify_generation_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para gerar usuários'}), 403
    
    if quantity > 50:  # Limite de segurança
        return jsonify({'error': 'Quantidade máxima é 50 usuários'}), 400
    
    created_users = []
    
    for _ in range(quantity):
        # Gerar username único
        while True:
            username = generate_random_username()
            if not User.query.filter_by(username=username).first():
                break
        
        # Gerar senha aleatória
        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        user = User(username=username)
        user.set_password(password)
        user.expires_at = datetime.utcnow() + timedelta(days=int(days))
        
        db.session.add(user)
        created_users.append({
            'username': username,
            'password': password,
            'expires_at': user.expires_at.isoformat()
        })
    
    db.session.commit()
    
    return jsonify({
        'message': f'{quantity} usuários gerados com sucesso',
        'users': created_users
    }), 201

@user_bp.route('/admin/user/delete', methods=['DELETE'])
def delete_user():
    """Apagar usuário específico"""
    data = request.json
    discord_user_id = data.get('discord_user_id')
    username = data.get('username')
    
    # Verificar permissão
    if not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para apagar usuários'}), 403
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': f'Usuário {username} apagado com sucesso'}), 200

@user_bp.route('/admin/user/reset_all', methods=['DELETE'])
def reset_all_users():
    """Apagar todos os usuários (exceto admins com permissão)"""
    data = request.json
    discord_user_id = data.get('discord_user_id')
    
    # Verificar permissão
    if not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para resetar usuários'}), 403
    
    # Não permitir que usuários com permissão de geração sejam apagados
    users_to_delete = User.query.filter_by(is_admin=False).all()
    count = len(users_to_delete)
    
    for user in users_to_delete:
        db.session.delete(user)
    
    db.session.commit()
    
    return jsonify({'message': f'{count} usuários apagados com sucesso'}), 200

@user_bp.route('/admin/user/clear_expired', methods=['DELETE'])
def clear_expired_users():
    """Limpar usuários expirados"""
    data = request.json
    discord_user_id = data.get('discord_user_id')
    
    # Verificar permissão
    if not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para limpar usuários expirados'}), 403
    
    expired_users = User.query.filter(User.expires_at < datetime.utcnow()).all()
    count = len(expired_users)
    
    for user in expired_users:
        db.session.delete(user)
    
    db.session.commit()
    
    return jsonify({'message': f'{count} usuários expirados removidos'}), 200

@user_bp.route('/admin/users/list', methods=['GET'])
def list_users():
    """Listar todos os usuários"""
    discord_user_id = request.args.get('discord_user_id')
    
    # Verificar permissão
    if not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para listar usuários'}), 403
    
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

@user_bp.route('/admin/permissions/grant', methods=['POST'])
def grant_permission():
    """Dar permissão administrativa"""
    data = request.json
    granter_discord_id = data.get('granter_discord_id')
    target_discord_id = data.get('target_discord_id')
    target_username = data.get('target_username')
    can_generate = data.get('can_generate', False)
    
    # Verificar se quem está dando permissão tem permissão
    if not verify_admin_permission(granter_discord_id):
        return jsonify({'error': 'Sem permissão para conceder permissões'}), 403
    
    # Verificar se já existe
    existing = AdminPermission.query.filter_by(discord_user_id=target_discord_id).first()
    if existing:
        existing.can_generate_users = can_generate
        existing.granted_by = granter_discord_id
        existing.granted_at = datetime.utcnow()
    else:
        permission = AdminPermission(
            discord_user_id=target_discord_id,
            username=target_username,
            can_generate_users=can_generate,
            granted_by=granter_discord_id
        )
        db.session.add(permission)
    
    db.session.commit()
    
    return jsonify({'message': f'Permissão concedida para {target_username}'}), 200

@user_bp.route('/admin/permissions/revoke', methods=['DELETE'])
def revoke_permission():
    """Remover permissão administrativa"""
    data = request.json
    revoker_discord_id = data.get('revoker_discord_id')
    target_discord_id = data.get('target_discord_id')
    
    # Verificar se quem está removendo permissão tem permissão
    if not verify_admin_permission(revoker_discord_id):
        return jsonify({'error': 'Sem permissão para revogar permissões'}), 403
    
    permission = AdminPermission.query.filter_by(discord_user_id=target_discord_id).first()
    if not permission:
        return jsonify({'error': 'Permissão não encontrada'}), 404
    
    db.session.delete(permission)
    db.session.commit()
    
    return jsonify({'message': 'Permissão removida com sucesso'}), 200

@user_bp.route('/admin/permissions/list', methods=['GET'])
def list_permissions():
    """Listar usuários com permissão administrativa"""
    discord_user_id = request.args.get('discord_user_id')
    
    # Verificar permissão
    if not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para listar permissões'}), 403
    
    permissions = AdminPermission.query.all()
    return jsonify([perm.to_dict() for perm in permissions]), 200

# Rotas de cliente
@user_bp.route('/user/info', methods=['GET'])
def get_user_info():
    """Obter informações do usuário (sem HWID)"""
    username = request.args.get('username')
    
    if not username:
        return jsonify({'error': 'Username é obrigatório'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    user_data = user.to_dict(include_sensitive=True)
    # Remover HWID das informações retornadas
    user_data.pop('hwid', None)
    
    return jsonify(user_data), 200

@user_bp.route('/user/reset_hwid', methods=['POST'])
def reset_user_hwid():
    """Resetar HWID do usuário"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username é obrigatório'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    if user.reset_hwid():
        db.session.commit()
        return jsonify({'message': 'HWID resetado com sucesso', 'resets_remaining': 2 - user.hwid_reset_count}), 200
    else:
        return jsonify({'error': 'Limite de resets de HWID atingido'}), 400

@user_bp.route('/user/pause', methods=['POST'])
def pause_user_key():
    """Pausar chave do usuário"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username é obrigatório'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    if user.pause_key():
        db.session.commit()
        return jsonify({'message': 'Chave pausada com sucesso', 'pauses_remaining': 3 - user.pause_count}), 200
    else:
        return jsonify({'error': 'Não é possível pausar a chave'}), 400

@user_bp.route('/user/unpause', methods=['POST'])
def unpause_user_key():
    """Despausar chave do usuário"""
    data = request.json
    username = data.get('username')
    discord_user_id = data.get('discord_user_id')
    
    if not username:
        return jsonify({'error': 'Username é obrigatório'}), 400
    
    # Verificar se tem permissão para despausar (pode ser o próprio usuário ou admin)
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    # Se discord_user_id for fornecido, verificar permissão de admin
    if discord_user_id and not verify_admin_permission(discord_user_id):
        return jsonify({'error': 'Sem permissão para despausar usuários'}), 403
    
    if user.unpause_key():
        db.session.commit()
        return jsonify({'message': 'Chave despausada com sucesso'}), 200
    else:
        return jsonify({'error': 'Usuário não está pausado'}), 400

# Rota de status
@user_bp.route('/status', methods=['GET'])
def get_status():
    """Obter status geral da API"""
    total_users = User.query.count()
    expired_users = User.query.filter(User.expires_at < datetime.utcnow()).count()
    logged_users = User.query.filter_by(is_logged_in=True).count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    return jsonify({
        'total_users': total_users,
        'expired_users': expired_users,
        'logged_users': logged_users,
        'admin_users': admin_users,
        'active_users': total_users - expired_users,
        'timestamp': datetime.utcnow().isoformat()
    }), 200
