const PasswordValidator = require('./index');

// Lista negra de contraseñas comunes o comprometidas (aunque cumplan complejidad)
const listaNegra = [
  'Passw0rd123!',
  'Admin123456!',
  'Ciberseguridad2026!'
];

const schema = new PasswordValidator();

schema
  .is().min(12)               // Mínimo 12 caracteres
  .is().max(64)               // Máximo 64 caracteres
  .has().uppercase(1)         // Al menos 1 letra mayúscula
 // .has().lowercase(1)         // Al menos 1 letra minúscula
  .has().digits(1)            // Al menos 1 número
  .has().symbols(1)           // Al menos 1 símbolo especial
  .has().not().spaces()       // Sin espacios en blanco
  .is().not().oneOf(listaNegra); // No pertenece a la lista negra

module.exports = schema;