-- Seleccionar la base de datos
USE ctf_db;

-- Crear la tabla flag
CREATE TABLE flag (
    flag_value VARCHAR(255) NOT NULL
);

-- Insertar un ejemplo de dato (opcional)
INSERT INTO flag (flag_value) VALUES ('CTF{example_flag}');

-- Crear la tabla flag
CREATE TABLE flag2 (
    flag_value VARCHAR(255) NOT NULL
);