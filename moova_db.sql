-- Base de datos: medicos_disponibles
CREATE DATABASE IF NOT EXISTS medicos_disponibles
    DEFAULT CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;

USE medicos_disponibles;

-- Tabla: admins
CREATE TABLE admins (
    id     INT(11)      NOT NULL AUTO_INCREMENT,
    nombre VARCHAR(100) NOT NULL,
    correo VARCHAR(100) NOT NULL,
    clave  VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY (correo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla: terapeutas
CREATE TABLE terapeutas (
    ID           INT(11)      NOT NULL AUTO_INCREMENT,
    Nombre       VARCHAR(100) NOT NULL,
    Especialidad VARCHAR(100) NOT NULL,
    Correo       VARCHAR(100) NOT NULL,
    Clave        VARCHAR(255) NOT NULL,
    PRIMARY KEY (ID),
    UNIQUE KEY (Correo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla: personas (pacientes que agendan cita)
CREATE TABLE personas (
    id       INT(11)     NOT NULL AUTO_INCREMENT,
    nombre   VARCHAR(100) NOT NULL,
    apellido VARCHAR(100) NOT NULL,
    dni      VARCHAR(15)  NOT NULL,
    telefono VARCHAR(20)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY (dni)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla: historial_citas
CREATE TABLE historial_citas (
    id             INT(11)      NOT NULL AUTO_INCREMENT,
    persona_id     INT(11)      NOT NULL,
    terapeuta_id   INT(11)      NOT NULL,
    fecha_cita     DATE         NOT NULL,
    descripcion    TEXT         DEFAULT NULL,
    estado         VARCHAR(20)  NOT NULL DEFAULT 'programada',
    -- estado puede ser: programada | cancelada | completada
    PRIMARY KEY (id),
    FOREIGN KEY (persona_id)   REFERENCES personas(id),
    FOREIGN KEY (terapeuta_id) REFERENCES terapeutas(ID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla: otp_verificaciones (códigos SMS para modificar/cancelar citas)
CREATE TABLE IF NOT EXISTS otp_verificaciones (
    id         INT(11)     NOT NULL AUTO_INCREMENT,
    dni        VARCHAR(15) NOT NULL,
    codigo     VARCHAR(6)  NOT NULL,
    accion     VARCHAR(20) NOT NULL,        -- 'modificar' | 'cancelar'
    intentos   INT(11)     NOT NULL DEFAULT 0,
    expira_en  DATETIME    NOT NULL,
    usado      TINYINT(1)  NOT NULL DEFAULT 0,
    creado_en  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_dni_accion (dni, accion)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
