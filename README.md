# Auth

Auth é um serviço central do **Nota Social**, responsável pela autenticação dos usuários que interagem com o ecossistema. Este serviço gerencia o processo de login, utilizando integração com o Keycloak para gerenciamento de identidade.

## Como funciona

 - Autenticação de Usuários: O serviço Auth valida as credenciais dos usuários, criados no Register, realizando autenticação via Keycloak.

## Funcionalidades principais

 - Login com Keycloak: Permite que usuários realizem login utilizando credenciais armazenadas no Keycloak

## Tecnologias utilizadas

- Keycloak: Sistema de gerenciamento de identidade e acesso, utilizado para autenticação, autorização e gerenciamento de usuários.
- Spring Security: Framework de segurança para controle de autenticação e autorização no serviço.
- JWT (JSON Web Token): Para autenticação.
- OAuth2: Para implementar a autenticação por meio do fluxo Resource Owner Password Credentials, garantindo integração com o Keycloak.
- Spring Boot: Framework para criação e gestão do serviço Auth, integrando com o Keycloak e outros componentes do ecossistema.

## Integração com o ecossistema Nota Social

O Auth é o ponto de autenticação do ecossistema Nota Social, sendo responsável por autenticar usuários que interagem com os outros serviços como Register, ReceiptScan, Catalog, e Social. Ele garante que apenas usuários autenticados possam acessar dados sensíveis e interagir com a plataforma de maneira segura, enquanto fornece um gerenciamento centralizado de identidade com Keycloak.
 
