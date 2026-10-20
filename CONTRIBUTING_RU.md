# Участие в GeniaFirewall

[English](CONTRIBUTING.md)

Спасибо за тестирование и развитие GeniaFirewall. Это security-sensitive firewall и Windows-служба, поэтому даже небольшое изменение policy может влиять на всю сеть системы. Изменения должны быть понятными, воспроизводимыми и безопасно откатываться.

## Писать код необязательно

Полезный вклад:

- воспроизводить ошибки на Windows 10/11;
- тестировать Ethernet, Wi-Fi, LAN, VPN и TUN;
- проверять входящие и исходящие правила приложений;
- улучшать документацию и локализацию;
- предлагать UI/UX;
- проверять WFP, lifecycle службы, ACL, IPC и cleanup;
- присылать небольшие целевые исправления.

Публичная тестовая матрица: [TESTING_RU.md](TESTING_RU.md).

## Среда разработки

- Windows 10/11 x64
- .NET 10 SDK
- Git
- права администратора для runtime-тестов службы/WFP

Базовая сборка:

```cmd
dotnet restore GeniaFirewall.sln
dotnet build GeniaFirewall.sln --configuration Release
```

## Требования к Pull Request

Делайте PR узким по смыслу. Опишите:

- какую проблему он решает;
- какой backend затронут;
- меняются ли WFP layers, actions, weights, directions, interface scope или cleanup;
- меняются ли привилегии службы, ACL, IPC, persistence, установка или rollback;
- что проверено на реальной Windows.

Не добавляйте publish output, бинарники, личные журналы, captured traffic, пароли, приватные пути, сертификаты, signing material и machine-specific state.

## Security-sensitive изменения

Для WFP/service изменений обязательно описывайте security impact. Любое fail-open поведение должно быть явно указано. Cleanup, rollback, backend handoff и reboot входят в задачу и должны тестироваться вместе с основным изменением.

## Минимальный checklist PR

- Release build проходит;
- CI зелёный;
- CodeQL зелёный;
- Allow/Block/Ask не изменились случайно;
- направленные правила проверены, если менялся policy mapping;
- Block all проверен, если менялись глобальные фильтры;
- после backend switch нет остаточных WFP-фильтров GeniaFirewall;
- reboot проверен, если менялись persistence/lifecycle.

## Уязвимости

Не публикуйте предполагаемую уязвимость в обычном Issue или PR. Следуйте [SECURITY.md](SECURITY.md) и используйте приватный GitHub Security Advisory.
