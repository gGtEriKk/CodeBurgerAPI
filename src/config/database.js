module.exports = {
  dialect: 'postgres',
  host: 'localhost',
  username: 'postgres',
  password: 'erikdev',
  database: 'codeburger',
  define: {
    timestamps: true, /* adiciona os campos 'createdAt' e 'updatedAt' automaticamente, ao criar um dado */
    underscored: true,
    underscoredAll: true, /* os nomes de cada dado de uma tabela fica no estilo 'snake_case' */
  },
}
