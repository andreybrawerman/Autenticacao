package com.pucpr.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UsuarioRepository {
    private final String FILE_PATH = "usuarios.json";
    private final ObjectMapper mapper = new ObjectMapper();

    public Optional<Usuario> findByEmail(String email) {
        List<Usuario> usuarios = findAll();

        return usuarios.stream()
                .filter(u -> u.getEmail().equalsIgnoreCase(email))
                .findFirst(); // 4. Retorna um Optional
    }

    public List<Usuario> findAll() {
        File arquivo = new File(FILE_PATH);

        if (!arquivo.exists() || arquivo.length() == 0) {
            return new ArrayList<>();
        }

        try {
            return mapper.readValue(arquivo, new TypeReference<List<Usuario>>(){});
        } catch (IOException e) {
            System.out.println("Erro ao ler arquivo: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public void save(Usuario usuario) throws IOException {
        List<Usuario> usuarios = findAll();

        if (findByEmail(usuario.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Erro: O e-mail já está cadastrado.");
        }

        usuarios.add(usuario);

        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(FILE_PATH), usuarios);
    }
}