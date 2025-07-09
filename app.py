# -*- coding: utf-8 -*-

# --- IMPORTAÇÕES ---
import os
import datetime
import requests
import math
from functools import wraps

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, Dict, List

load_dotenv()

# Instancia a aplicação Flask
app = Flask(__name__)
CORS(app)

# --- CONFIGURAÇÃO DAS VARIÁVEIS DE AMBIENTE ---
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.config["MONGO_DB_NAME"] = os.environ.get("MONGO_DB_NAME")
app.config["GOOGLE_API_KEY"] = os.environ.get("GOOGLE_API_KEY")

# Chaves específicas para a integração com a Meta (Facebook/Instagram)
META_GRAPH_API_URL = "https://graph.facebook.com/v20.0" # Recomenda-se usar a versão mais recente
META_PAGE_ACCESS_TOKEN = os.environ.get("META_PAGE_ACCESS_TOKEN")
META_VERIFY_TOKEN = os.environ.get("META_VERIFY_TOKEN") # Seu token secreto para o webhook

# --- CONEXÃO COM O BANCO DE DADOS MONGODB ---
try:
    client = MongoClient(app.config["MONGO_URI"])
    db = client[app.config["MONGO_DB_NAME"]]
    users_collection = db.users
    stores_collection = db.stores
    print("Conexão com o MongoDB estabelecida com sucesso.")
except Exception as e:
    print(f"Erro fatal ao conectar com o MongoDB: {e}")
    exit(1) # Encerra a aplicação se não conseguir conectar ao DB


# --- MODELOS DE DADOS (PYDANTIC) ---

class Coordenadas(BaseModel):
    lat: float
    lng: float

class StoreModel(BaseModel):
    id: Optional[str] = Field(default=None, alias='_id')
    f1code: str # Código da loja/vendedor no CRM F1Sales
    nome: str
    coordenadas: Coordenadas

class LeadCustomerModel(BaseModel):
    name: str
    phone: str
    email: str
    cep: str

class PublicLeadPayload(BaseModel):
    customer: LeadCustomerModel
    product: Dict[str, str]
    source: Dict[str, str]
    message: str
    description: str


# --- SERVIÇOS E LÓGICA DE NEGÓCIO ---

class GeolocationService:
    """Encapsula a lógica de geolocalização e busca de lojas."""

    def get_coords_from_cep(self, cep: str) -> Optional[Coordenadas]:
        """Busca coordenadas geográficas (lat, lng) a partir de um CEP."""
        try:
            cep_numerico = ''.join(filter(str.isdigit, cep))
            if len(cep_numerico) != 8: return None

            # 1. Tenta obter o endereço com a API ViaCEP (rápida e focada no Brasil)
            via_cep_res = requests.get(f"https://viacep.com.br/ws/{cep_numerico}/json/")
            via_cep_res.raise_for_status()
            cep_data = via_cep_res.json()
            if cep_data.get("erro"): return None

            # 2. Usa o endereço obtido para conseguir as coordenadas precisas com a API do Google
            endereco_completo = f"{cep_data['logradouro']}, {cep_data['bairro']}, {cep_data['localidade']} - {cep_data['uf']}"
            google_api_url = "https://maps.googleapis.com/maps/api/geocode/json"
            params = {"address": endereco_completo, "key": app.config["GOOGLE_API_KEY"]}
            geo_res = requests.get(google_api_url, params=params)
            geo_res.raise_for_status()
            geo_data = geo_res.json()

            if geo_data.get("status") == "OK":
                location = geo_data["results"][0]["geometry"]["location"]
                return Coordenadas(lat=location["lat"], lng=location["lng"])
            return None
        except requests.exceptions.RequestException as e:
            print(f"Erro ao chamar API externa de geolocalização: {e}")
            return None

    def _haversine_distance(self, coords1: Coordenadas, coords2: Coordenadas) -> float:
        """Calcula a distância em quilômetros entre duas coordenadas geográficas."""
        R = 6371  # Raio da Terra em km
        d_lat = math.radians(coords2.lat - coords1.lat)
        d_lon = math.radians(coords2.lng - coords1.lng)
        a = (math.sin(d_lat / 2) ** 2) + math.cos(math.radians(coords1.lat)) * math.cos(math.radians(coords2.lat)) * (math.sin(d_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def find_nearest_store(self, client_coords: Coordenadas) -> Optional[dict]:
        """Encontra a loja mais próxima no banco de dados com base nas coordenadas do cliente."""
        all_stores = list(stores_collection.find({}))
        if not all_stores: return None

        # Calcula a distância para cada loja e encontra a menor
        store_distances = []
        for store_data in all_stores:
            try:
                store_coords = Coordenadas(**store_data["coordenadas"])
                distance = self._haversine_distance(client_coords, store_coords)
                store_distances.append((distance, store_data))
            except ValidationError:
                # Ignora lojas com dados de coordenadas inválidos no DB
                continue

        if not store_distances: return None

        # Ordena pela distância e pega a loja mais próxima
        store_distances.sort(key=lambda x: x[0])
        nearest_store = store_distances[0][1]
        min_distance = store_distances[0][0]

        # Lógica de fallback: se a loja mais próxima estiver muito longe, atribui a um vendedor padrão
        DISTANCE_THRESHOLD_KM = 100
        if min_distance > DISTANCE_THRESHOLD_KM:
            # Este f1code 'erik.santos@flex.es' é um fallback, idealmente viria de uma config
            return stores_collection.find_one({"f1code": "erik.santos@flex.es"})
        
        return nearest_store


class F1SalesService:
    """Encapsula a comunicação com a API do CRM F1Sales."""
    API_BASE_URL = "https://simmons.f1sales.org/public/api/v1"
    HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    def send_lead(self, payload: PublicLeadPayload, store_f1code: Optional[str] = None):
        """Envia um lead para a F1Sales e, opcionalmente, o atribui a um vendedor."""
        customer = payload.customer
        lead_payload = {
            "lead": {
                "customer": { "name": customer.name, "phone": customer.phone, "email": customer.email, "address": {"cep": customer.cep} },
                "product": payload.product,
                "source": payload.source,
                "message": payload.message,
                "description": payload.description,
            }
        }
        try:
            # 1. Cria o lead no CRM
            create_response = requests.post(f"{self.API_BASE_URL}/leads", json=lead_payload, headers=self.HEADERS)
            create_response.raise_for_status()
            lead_data = create_response.json()
            f1_lead_id = lead_data.get("data", {}).get("id")
            if not f1_lead_id:
                raise Exception("API F1Sales não retornou um ID para o lead criado.")
            
            # 2. Se um código de loja/vendedor foi fornecido, atribui o lead
            if store_f1code:
                assign_payload = {"lead": {"salesman": {"email": store_f1code}}}
                assign_response = requests.put(f"{self.API_BASE_URL}/leads/{f1_lead_id}", json=assign_payload, headers=self.HEADERS)
                assign_response.raise_for_status()
                return assign_response.json() # Retorna a resposta da atribuição
            
            return lead_data # Retorna a resposta da criação do lead
        except requests.exceptions.RequestException as e:
            error_body = e.response.json() if e.response and e.response.headers.get('Content-Type') == 'application/json' else str(e)
            raise Exception(f"Erro na comunicação com a API F1Sales: {error_body}")


# --- INSTÂNCIAS DOS SERVIÇOS ---
geolocation_service = GeolocationService()
f1_sales_service = F1SalesService()


# --- DECORATORS DE AUTENTICAÇÃO ---
# Decorators são funções que modificam o comportamento de outras funções.

def token_required(f):
    """Decorator para rotas que exigem um token JWT válido."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            # O token é enviado no formato "Bearer <token>"
            token = request.headers["Authorization"].split(" ")[1]
        
        if not token:
            return jsonify({"message": "Token de autenticação está faltando!"}), 401
        
        try:
            # Decodifica o token para verificar sua validade e obter os dados do usuário
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = users_collection.find_one({"_id": ObjectId(data["user_id"])})
            if not current_user:
                return jsonify({"message": "Usuário do token não encontrado."}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expirou! Faça login novamente."}), 401
        except (jwt.InvalidTokenError, Exception) as e:
            return jsonify({"message": "Token inválido!", "error": str(e)}), 401
        
        # Passa o usuário encontrado para a rota
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator que exige que o usuário tenha a role 'admin'."""
    @wraps(f)
    @token_required # Este decorator já inclui a verificação do token
    def decorated(current_user, *args, **kwargs):
        if current_user.get("role") != "admin":
            return jsonify({"message": "Acesso negado: Requer privilégios de administrador."}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# --- FUNÇÕES HELPERS ---
def serialize_doc(doc):
    """Converte o ObjectId do MongoDB para string para ser serializável em JSON."""
    if doc and "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc


# --- ROTAS DA API ---

@app.route("/", methods=["GET"])
def home():
    """Rota inicial para verificar se a API está online."""
    return jsonify({"status": "API Simmons Leads - Online", "version": "2.0.0"})

# --- ROTAS DE WEBHOOK (INTEGRAÇÃO META) ---

@app.route("/webhook/meta", methods=["GET", "POST"])
def meta_webhook_handler():
    """Endpoint para receber e processar webhooks de formulários de leads da Meta."""
    
    # Etapa de verificação: acontece uma única vez ao configurar o webhook no painel da Meta.
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        
        if mode == "subscribe" and token == META_VERIFY_TOKEN:
            print("Webhook da Meta verificado com sucesso!")
            return challenge, 200
        else:
            print("Falha na verificação do webhook da Meta. Tokens não correspondem.")
            return "Token de verificação inválido", 403

    # Processamento de novos leads recebidos via POST
    if request.method == "POST":
        data = request.get_json()
        print(f"Payload recebido da Meta: {data}")

        if data.get("object") == "page":
            for entry in data.get("entry", []):
                for change in entry.get("changes", []):
                    if change.get("field") == "leadgen":
                        leadgen_id = change.get("value", {}).get("leadgen_id")
                        if not leadgen_id:
                            continue

                        try:
                            # Busca os detalhes do lead usando a API Graph da Meta
                            url = f"{META_GRAPH_API_URL}/{leadgen_id}?access_token={META_PAGE_ACCESS_TOKEN}"
                            response = requests.get(url)
                            response.raise_for_status()
                            lead_details = response.json()
                            print(f"🔍 Detalhes do lead obtidos da Meta: {lead_details}")

                            # Mapeia os campos do formulário para um dicionário
                            mapped_data = {field["name"]: field["values"][0] for field in lead_details.get("field_data", [])}

                            # Monta o payload no formato que nosso sistema entende
                            payload_data = {
                                "customer": {
                                    "name": mapped_data.get("full_name", "Nome não fornecido"),
                                    "phone": mapped_data.get("whatsapp_number", ""),
                                    "email": mapped_data.get("email", ""),
                                    "cep": mapped_data.get("zip_code", "")
                                },
                                "product": {"name": "Produto do Formulário Meta", "size": "Não informado"},
                                "source": {"origin": "Meta Lead Ad", "campaign": change.get("value", {}).get("campaign_name", "N/A")},
                                "message": "Lead gerado via formulário do Facebook/Instagram.",
                                "description": f"Lead ID da Meta: {leadgen_id}"
                            }
                            
                            payload = PublicLeadPayload(**payload_data)

                            # Usa os serviços para atribuir o lead
                            client_coords = geolocation_service.get_coords_from_cep(payload.customer.cep)
                            store_f1code_to_assign = None
                            if client_coords:
                                nearest_store = geolocation_service.find_nearest_store(client_coords)
                                if nearest_store:
                                    store_f1code_to_assign = nearest_store["f1code"]
                                    print(f"Lead {leadgen_id} será atribuído para a loja {nearest_store['nome']}")
                            
                            f1_sales_service.send_lead(payload, store_f1code_to_assign)
                            print(f"Lead {leadgen_id} processado e enviado para F1Sales.")

                        except Exception as e:
                            print(f"Erro ao processar o lead {leadgen_id}: {e}")
                            # Retorna 200 OK mesmo em caso de erro para evitar que a Meta reenvie a notificação.
        
        return "EVENT_RECEIVED", 200
    
    return "Método não suportado", 405


# --- ROTAS DE AUTENTICAÇÃO E USUÁRIOS ---

@app.route("/register", methods=["POST"])
@admin_required # Apenas admins podem registrar novos usuários
def register(current_user):
    data = request.get_json()
    username, password, role = data.get("username"), data.get("password"), data.get("role", "user")
    if not username or not password:
        return jsonify({"message": "Usuário e senha são obrigatórios."}), 400
    if users_collection.find_one({"username": username}):
        return jsonify({"message": "Este nome de usuário já existe."}), 409
    
    users_collection.insert_one({
        "username": username,
        "password": generate_password_hash(password),
        "role": role
    })
    return jsonify({"message": "Usuário registrado com sucesso!"}), 201

@app.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({"message": "Login via Basic Auth (usuário e senha) é necessário."}), 401
    
    user = users_collection.find_one({"username": auth.username})
    if not user or not check_password_hash(user["password"], auth.password):
        return jsonify({"message": "Usuário ou senha inválidos."}), 401
    
    # Gera o token JWT com validade de 24 horas
    token = jwt.encode({
        "user_id": str(user["_id"]),
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config["SECRET_KEY"], algorithm="HS256")
    
    return jsonify({"token": token})


# --- ROTAS DE LOJAS (STORES) ---

@app.route("/stores", methods=["POST"])
@admin_required
def create_store(current_user):
    try:
        store_data = StoreModel(**request.get_json())
        if stores_collection.find_one({"f1code": store_data.f1code}):
            return jsonify({"message": f"Loja com f1code '{store_data.f1code}' já existe."}), 409
        
        result = stores_collection.insert_one(store_data.dict(by_alias=True, exclude_none=True))
        created_store = stores_collection.find_one({"_id": result.inserted_id})
        return jsonify(serialize_doc(created_store)), 201
    except ValidationError as e:
        return jsonify({"message": "Dados inválidos", "errors": e.errors()}), 400
    except Exception as e:
        return jsonify({"message": "Erro interno do servidor", "error": str(e)}), 500

@app.route("/stores", methods=["GET"])
@token_required
def get_all_stores(current_user):
    stores = [serialize_doc(store) for store in stores_collection.find()]
    return jsonify(stores), 200

@app.route("/stores/find-nearest", methods=["POST"])
def find_nearest_store_route():
    """Rota pública para encontrar a loja mais próxima com base em um CEP."""
    data = request.get_json()
    cep = data.get("cep")
    if not cep:
        return jsonify({"message": "O campo 'cep' é obrigatório no corpo da requisição."}), 400

    try:
        client_coords = geolocation_service.get_coords_from_cep(cep)
        if not client_coords:
            return jsonify({"message": "CEP inválido ou não foi possível obter as coordenadas."}), 400

        nearest_store = geolocation_service.find_nearest_store(client_coords)
        if not nearest_store:
            return jsonify({"message": "Nenhuma loja foi encontrada na região."}), 404
        
        return jsonify(serialize_doc(nearest_store)), 200
    except Exception as e:
        print(f"Erro na rota /stores/find-nearest: {e}")
        return jsonify({"message": "Ocorreu um erro interno ao buscar a loja.", "error": str(e)}), 500

@app.route("/stores/<store_id>", methods=["PUT"])
def update_store( store_id):
    try:
        store_data = StoreModel(**request.get_json())
        update_payload = store_data.dict(by_alias=True, exclude_unset=True, exclude={'id'})
        result = stores_collection.update_one({"_id": ObjectId(store_id)}, {"$set": update_payload})
        if result.matched_count:
            updated_store = stores_collection.find_one({"_id": ObjectId(store_id)})
            return jsonify(serialize_doc(updated_store)), 200
        return jsonify({"message": "Loja não encontrada."}), 404
    except ValidationError as e:
        return jsonify({"message": "Dados inválidos", "errors": e.errors()}), 400
    except Exception as e:
        return jsonify({"message": "Erro interno do servidor", "error": str(e)}), 500

@app.route("/stores/<store_id>", methods=["DELETE"])
def delete_store( store_id):
    try:
        result = stores_collection.delete_one({"_id": ObjectId(store_id)})
        if result.deleted_count:
            return jsonify({"message": "Loja deletada com sucesso."}), 200
        return jsonify({"message": "Loja não encontrada."}), 404
    except Exception as e:
        return jsonify({"message": "Erro interno do servidor", "error": str(e)}), 500


# --- ROTAS DE LEADS (MANUAIS) ---
# Estas rotas podem ser usadas para testes ou para integrar com outros sistemas que não a Meta.

@app.route("/leads/assign", methods=["POST"])
def create_and_assign_lead():
    try:
        payload = PublicLeadPayload(**request.get_json())
        client_coords = geolocation_service.get_coords_from_cep(payload.customer.cep)
        if not client_coords:
            return jsonify({"message": "CEP inválido ou não foi possível encontrar as coordenadas."}), 400
        
        nearest_store = geolocation_service.find_nearest_store(client_coords)
        if not nearest_store:
            return jsonify({"message": "Nenhuma loja encontrada para atribuição."}), 404
        
        f1_response = f1_sales_service.send_lead(payload, nearest_store["f1code"])
        return jsonify({
            "message": "Lead enviado e atribuído com sucesso no F1Sales!",
            "f1_sales_response": f1_response,
            "assigned_store": serialize_doc(nearest_store)
        }), 201
    except ValidationError as e:
        return jsonify({"message": "Dados do lead inválidos", "errors": e.errors()}), 400
    except Exception as e:
        return jsonify({"message": "Erro ao processar lead", "error": str(e)}), 500


# --- INICIALIZAÇÃO DO SERVIDOR ---
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
