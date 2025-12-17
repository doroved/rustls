# Patches rustls


Получаем теги оригинального репозитория и переключаемся на нужную версию
```bash
git remote add upstream https://github.com/rustls/rustls.git
git fetch upstream --tags
git checkout v/0.23.35
```

В проекте в Cargo.toml подключаем патчи
```toml
[patch.crates-io]
# Ваш патч для rustls
rustls = { git = 'https://github.com/doroved/rustls.git' }
# Вы также должны явно добавить патч для pki-types сюда!
rustls-pki-types = { git = 'https://github.com/doroved/pki-types.git' }
```
