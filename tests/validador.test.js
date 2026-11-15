const { expect } = require('chai');
const validador = require('../src/validador');

describe('Validación de Contraseñas Seguras (Tarea Ciberseguridad)', function () {

  describe('Contraseñas válidas', function () {
    it('debe aceptar una contraseña robusta que cumpla todos los requisitos', function () {
      expect(validador.validate('C1b3r$egur1dad!')).to.be.true;
    });

    it('debe aceptar una contraseña en el límite exacto de 12 caracteres', function () {
      expect(validador.validate('Abcdef12345!')).to.be.true;
    });

    it('debe aceptar una contraseña en el límite exacto de 64 caracteres', function () {
      const clave64 = 'A1!' + 'a'.repeat(61);
      expect(clave64).to.have.lengthOf(64);
      expect(validador.validate(clave64)).to.be.true;
    });
  });

  describe('Control de longitud (mínimo 12, máximo 64)', function () {
    it('debe rechazar una contraseña de 11 caracteres', function () {
      expect(validador.validate('Abcdef1234!')).to.be.false;
      expect(validador.validate('Abcdef1234!', { list: true })).to.include('min');
    });

    it('debe rechazar una contraseña vacía', function () {
      expect(validador.validate('')).to.be.false;
    });

    it('debe rechazar una contraseña de 65 caracteres', function () {
      const clave65 = 'A1!' + 'a'.repeat(62);
      expect(clave65).to.have.lengthOf(65);
      expect(validador.validate(clave65)).to.be.false;
      expect(validador.validate(clave65, { list: true })).to.include('max');
    });
  });

  describe('Complejidad de caracteres', function () {
    it('debe rechazar si falta al menos una mayúscula', function () {
      expect(validador.validate('c1b3r$egur1dad!')).to.be.false;
      expect(validador.validate('c1b3r$egur1dad!', { list: true })).to.include('uppercase');
    });

    it('debe rechazar si falta al menos una minúscula', function () {
      expect(validador.validate('C1B3R$EGUR1DAD!')).to.be.false;
      expect(validador.validate('C1B3R$EGUR1DAD!', { list: true })).to.include('lowercase');
    });

    it('debe rechazar si falta al menos un número', function () {
      expect(validador.validate('Ciber$eguridad!')).to.be.false;
      expect(validador.validate('Ciber$eguridad!', { list: true })).to.include('digits');
    });

    it('debe rechazar si falta al menos un símbolo especial', function () {
      expect(validador.validate('C1b3rSegur1dad2026')).to.be.false;
      expect(validador.validate('C1b3rSegur1dad2026', { list: true })).to.include('symbols');
    });
  });

  describe('Restricciones de seguridad (espacios y lista negra)', function () {
    it('debe rechazar contraseñas con espacios en medio', function () {
      expect(validador.validate('C1b3r $egur1dad!')).to.be.false;
      expect(validador.validate('C1b3r $egur1dad!', { list: true })).to.include('spaces');
    });

    it('debe rechazar contraseñas con espacios al inicio o al final', function () {
      expect(validador.validate(' C1b3r$egur1dad!')).to.be.false;
      expect(validador.validate('C1b3r$egur1dad! ')).to.be.false;
    });

    it('debe rechazar contraseñas incluidas en la lista negra aunque cumplan complejidad', function () {
      expect(validador.validate('Passw0rd123!')).to.be.false;
      expect(validador.validate('Admin123456!')).to.be.false;
      expect(validador.validate('Ciberseguridad2026!', { list: true })).to.include('oneOf');
    });
  });

});