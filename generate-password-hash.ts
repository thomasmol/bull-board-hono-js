import bcrypt from 'bcrypt';
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('Enter the password to hash: ', (password) => {
  const saltRounds = 10;
  const hash = bcrypt.hashSync(password, saltRounds);
  console.log('Hashed password:');
  console.log(hash);
  rl.close();
});