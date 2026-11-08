# Acceso al DFSha compartido

El clúster está en AWS Academy, región `us-east-1`. Los tres hosts ejecutan Docker;
no necesitas instalar Docker en tu portátil para utilizar el cliente.

## Entrar desde el Mac de Sebastián

```bash
cd "/Users/mac/Desktop/dfsha proyecto/entrega-copia/dfsha-project"
chmod 600 deploy/aws/secrets/equipo/dfsha-sebastian.pem
ssh -i deploy/aws/secrets/equipo/dfsha-sebastian.pem dfsha-sebastian@3.236.40.198
```

El comando anterior entra a una terminal en AWS. Allí el comando `dfsha` ya está
instalado y configurado para los tres controles privados:

```bash
dfsha register sebastian
dfsha login sebastian
dfsha status
dfsha mkdir /documentos
dfsha ls /
```

`register` se hace una sola vez. Elige tu contraseña cuando se solicite. En otra
sesión solo necesitas `login` si no hay una sesión válida guardada. `exit` sale de SSH.

## Simón y Santiago

Cada integrante recibe únicamente su propia clave privada:

| Integrante | Archivo | Usuario SSH |
|---|---|---|
| Sebastián | `dfsha-sebastian.pem` | `dfsha-sebastian` |
| Simón | `dfsha-simon.pem` | `dfsha-simon` |
| Santiago | `dfsha-santiago.pem` | `dfsha-santiago` |

Las claves están en `deploy/aws/secrets/equipo/`, excluido de Git. Cada integrante
puede colocar su archivo en una carpeta privada y ejecutar, cambiando su nombre:

```bash
chmod 600 dfsha-simon.pem
ssh -i dfsha-simon.pem dfsha-simon@3.236.40.198
```

Los accesos de sistema no tienen permisos de administración ni acceso a Docker.
Cada uno tiene su propio directorio, configuración y sesión del cliente.

**Falta autorizar en el grupo de seguridad la IP pública de cada red externa.**
El grupo es `sg-00098d145ad23b771` (`dfsha-entrega-private`). Obtén tu IPv4 en
`https://checkip.amazonaws.com` y permite SSH/TCP 22 desde esa dirección `/32`.
Los puertos del servicio permanecen accesibles solo entre hosts del clúster.
Si cambia tu IP pública, hay que actualizar esa autorización.

La cuenta SSH y la cuenta DFSha son distintas: puedes entrar por SSH como
`dfsha-simon` e iniciar DFSha con un usuario propio o con el usuario compartido
que acuerde el equipo. Misma cuenta DFSha significa los mismos archivos y permisos;
cuentas DFSha diferentes tienen espacios privados.

## Subir un archivo que está en tu portátil

Primero, desde una terminal **local**, cópialo a tu directorio en la VM:

```bash
scp -i deploy/aws/secrets/equipo/dfsha-sebastian.pem \
  "$HOME/Downloads/Avanceidea 1.pdf" \
  dfsha-sebastian@3.236.40.198:~/avanceidea.pdf
```

Después entra por SSH y súbelo a DFSha:

```bash
dfsha put "$HOME/avanceidea.pdf" /documentos/avanceidea.pdf
dfsha stat /documentos/avanceidea.pdf
dfsha get /documentos/avanceidea.pdf "$HOME/avanceidea-recuperado.pdf"
sha256sum "$HOME/avanceidea.pdf" "$HOME/avanceidea-recuperado.pdf"
```

Dentro de SSH, `$HOME` corresponde a tu directorio **en AWS**, no al de tu Mac.
El primer `scp` transfiere el archivo a la VM; `dfsha put` lo incorpora al sistema
distribuido. Para llevar una descarga de la VM a tu Mac, usa `scp` en sentido inverso.

## Estado y conservación

Las direcciones públicas pueden cambiar al reiniciar las VM. Consulta los valores
vigentes en EC2 y actualiza los comandos de acceso. Los servicios usan direcciones
privadas. Si AWS Academy termina la sesión, debes volver a iniciar el laboratorio
y comprobar que los tres hosts estén encendidos.

La carpeta `implementacion/dfsha-project` corresponde a la práctica anterior;
la aplicación verificada y sus evidencias están en `entrega-copia/dfsha-project`.
Los archivos subidos al clúster local no se transfieren automáticamente a AWS.
