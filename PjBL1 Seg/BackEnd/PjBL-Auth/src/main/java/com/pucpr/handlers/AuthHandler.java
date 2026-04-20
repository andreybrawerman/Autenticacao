package com.pucpr.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Optional;

public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    static class AuthRequest {
        public String name;
        public String email;
        public String password;
        public String role;
    }

    private boolean lidarComCors(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
            exchange.sendResponseHeaders(204, -1);
            return true;
        }
        return false;
    }

    public void handleLogin(HttpExchange exchange) throws IOException {
        if (lidarComCors(exchange)) return;

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            AuthRequest request = mapper.readValue(exchange.getRequestBody(), AuthRequest.class);
            Optional<Usuario> userOpt = repository.findByEmail(request.email);

            if (userOpt.isPresent() && BCrypt.checkpw(request.password, userOpt.get().getSenhaHash())) {
                String token = jwtService.generateToken(userOpt.get());
                String jsonResponse = "{\"token\": \"" + token + "\", \"message\": \"Login efetuado com sucesso\"}";
                enviarResposta(exchange, 200, jsonResponse);
            } else {
                enviarResposta(exchange, 401, "{\"message\": \"E-mail ou senha inválidos\"}");
            }
        } catch (Exception e) {
            enviarResposta(exchange, 400, "{\"message\": \"Erro ao processar a requisição de login\"}");
        }
    }

    public void handleRegister(HttpExchange exchange) throws IOException {
        if (lidarComCors(exchange)) return;

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            AuthRequest request = mapper.readValue(exchange.getRequestBody(), AuthRequest.class);

            if (repository.findByEmail(request.email).isPresent()) {
                enviarResposta(exchange, 400, "{\"message\": \"Este e-mail já está em uso.\"}");
                return;
            }

            String hashDaSenha = BCrypt.hashpw(request.password, BCrypt.gensalt(12));
            String roleDefinido = (request.role != null) ? request.role : "UTILIZADOR";
            Usuario novoUsuario = new Usuario(request.name, request.email, hashDaSenha, roleDefinido);

            repository.save(novoUsuario);

            enviarResposta(exchange, 201, "{\"message\": \"Utilizador criado com sucesso!\"}");

        } catch (Exception e) {
            System.out.println("Erro no backend: " + e.getMessage());
            enviarResposta(exchange, 400, "{\"message\": \"Falha ao registar o utilizador.\"}");
        }
    }

    private void enviarResposta(HttpExchange exchange, int statusCode, String resposta) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");

        byte[] bytes = resposta.getBytes("UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);

        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }
}