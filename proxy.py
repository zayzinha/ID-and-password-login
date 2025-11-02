import json
import os
from datetime import datetime, timedelta
from mitmproxy import http, connection as connections, tcp


class ProxyAddon:
    def __init__(self):
        self.connections = {}
        self.login_data = None
        self.login_file_mtime = None
        self.load_login_data()
    
    def load_login_data(self):
        try:
            if os.path.exists('login.json'):
                current_mtime = os.path.getmtime('login.json')
                
                if self.login_file_mtime == current_mtime and self.login_data is not None:
                    return self.login_data
                
                with open('login.json', 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        self.login_data = data[0]
                    else:
                        self.login_data = data
                
                self.login_file_mtime = current_mtime
                
                print(f"login.json carregado: uid={self.login_data.get('uid') if self.login_data else 'N/A'}, password={self.login_data.get('password', '')[:20] if self.login_data else 'N/A'}...")
                return self.login_data
            else:
                print("Arquivo login.json nao encontrado")
                self.login_data = None
                self.login_file_mtime = None
                return None
        except Exception as e:
            print(f"Erro ao carregar login.json: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def check_and_reload_login(self):
        try:
            if os.path.exists('login.json'):
                current_mtime = os.path.getmtime('login.json')
                if self.login_file_mtime != current_mtime:
                    print("login.json modificado detectado, recarregando...")
                    old_uid = self.login_data.get('uid') if self.login_data else None
                    self.load_login_data()
                    new_uid = self.login_data.get('uid') if self.login_data else None
                    if old_uid != new_uid:
                        print(f"Dados atualizados: uid {old_uid} -> {new_uid}")
        except Exception as e:
            print(f"Erro ao verificar login.json: {e}")

    def client_connected(self, client: connections.Client):
        self.connections[client] = datetime.utcnow()

    def client_disconnected(self, client: connections.Client):
        self.connections.pop(client, None)

    async def request(self, flow: http.HTTPFlow):
        self.check_and_reload_login()
        
        url_lower = flow.request.pretty_url.lower()
        if "token:grant" in url_lower or "tokengrant" in url_lower or ("token" in url_lower and "grant" in url_lower):
            print(f"Interceptando TokenGrant: {flow.request.pretty_url}")
            
            try:
                if not self.login_data:
                    print("Dados de login nao carregados, pulando modificacao")
                else:
                    request_content = flow.request.content
                    original_content_length = len(request_content)
                    
                    if not request_content:
                        print("Request vazia!")
                
                    was_encrypted = False
                    try:
                        from AES import AESUtils
                        AES = AESUtils()
                        if len(request_content) % 16 == 0 and len(request_content) > 0:
                            hex_str = request_content.hex()
                            decrypted_content = AES.decrypt_aes_cbc(hex_str)
                            if decrypted_content and len(decrypted_content) > 0:
                                request_content = decrypted_content
                                was_encrypted = True
                                print(f"Request descriptografada ({len(request_content)} bytes)")
                    except ImportError:
                        pass
                    except Exception as e:
                        pass
                    
                    try:
                        if isinstance(request_content, bytes):
                            request_text = request_content.decode('utf-8', errors='ignore')
                        else:
                            request_text = request_content
                        
                        request_text = request_text.strip()
                        
                        request_json = None
                        try:
                            request_json = json.loads(request_text)
                        except json.JSONDecodeError as je:
                            if 'application/json' in flow.request.headers.get('Content-Type', ''):
                                raise je
                            else:
                                from urllib.parse import parse_qs, unquote
                                parsed = parse_qs(request_text)
                                request_json = {}
                                for key, value in parsed.items():
                                    if len(value) == 1:
                                        request_json[key] = value[0]
                                    else:
                                        request_json[key] = value
                        
                        if request_json is None:
                            print("Nao foi possivel parsear a request")
                            return
                        
                        original_uid = request_json.get('uid')
                        original_password = request_json.get('password')
                        
                        new_uid = self.login_data.get('uid')
                        new_password = self.login_data.get('password')
                        
                        if isinstance(original_uid, int):
                            new_uid = int(new_uid) if new_uid else new_uid
                        elif isinstance(original_uid, str):
                            new_uid = str(new_uid) if new_uid else new_uid
                        
                        request_json['uid'] = new_uid
                        request_json['password'] = new_password
                        
                        print(f"UID alterado: {original_uid} -> {request_json['uid']}")
                        print(f"Password alterado: {original_password[:20] if original_password else 'N/A'}... -> {request_json['password'][:20]}...")
                        
                        modified_json_str = json.dumps(request_json, separators=(',', ':'))
                        modified_content = modified_json_str.encode('utf-8')
                        
                        if was_encrypted:
                            try:
                                from AES import AESUtils
                                AES = AESUtils()
                                encrypted_content = AES.encrypt_aes_cbc(modified_content)
                                flow.request.content = encrypted_content
                                print(f"Request re-criptografada ({len(encrypted_content)} bytes)")
                            except Exception as e:
                                flow.request.content = modified_content
                        else:
                            flow.request.content = modified_content
                        
                        flow.request.headers["Content-Length"] = str(len(flow.request.content))
                        
                        print(f"TokenGrant modificado com sucesso!")
                        
                    except Exception as e:
                        print(f"Erro ao processar TokenGrant: {e}")
                        import traceback
                        traceback.print_exc()
                        
            except Exception as e:
                print(f"Erro ao interceptar TokenGrant: {e}")
                import traceback
                traceback.print_exc()
        
        start_time = self.connections.get(flow.client_conn)
        if start_time and datetime.utcnow() - start_time > timedelta(minutes=5):
            ip = flow.client_conn.address[0]
            print(f"[AUTO-DISCONNECT] {ip} kicked after 5 minutes")
            flow.kill()
            return

        try:
            client_ip = flow.client_conn.address[0]
            if client_ip:
                flow.request.headers["X-Client-IP"] = client_ip
                xff = flow.request.headers.get("X-Forwarded-For")
                flow.request.headers["X-Forwarded-For"] = f"{xff}, {client_ip}" if xff else client_ip
        except Exception:
            pass

    async def response(self, flow: http.HTTPFlow):
        pass

    def tcp_message(self, flow: tcp.TCPFlow):
            pass


addons = [ProxyAddon()]
