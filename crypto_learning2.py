from collections import deque
import re
from urllib.parse import unquote_plus
import pandas as pd
import time

# Patrones de expresión regular para detectar inyecciones SQL comunes, enstos son básicos, puede haber muchos tipos o sentencias sql DML
patrones_inyeccion_sql = [
    r"(\%27|\')\s*or\s*[\w\s]*\s*(\%3D|=)",  # Busca por '%27' o "'" seguido de 'or' y '='
    r"(\%2D|\-|\%2F|\%23|\#).*--",            # Busca comentarios SQL '--'
    r"(\%3B|;)",                              # Busca el punto y coma ';'
    r"(\%27|\')\s*or\s*1\%3D1\s*--\s*-",      # Busca el patron "' or 1=1 -- -"
    r"(\%27|\')\s*order\s*by\s*\d+\s*desc\s*--\s*-", # Busca el patrin "' order by N desc -- -" donde N es un número
    r"(\%27|\')\s*UNION\s*SELECT\s*'.*',\s*\d+\s*--\s*-", # Busca inyecciones que usan UNION SELECT con una cadena y un numero
    r"(\%27|\')\s*UNION\s*SELECT\s*\@\@SERVERNAME,\s*DB_NAME\(\)\s*--\s*-", # Busca el patrion para obtener información del servidor y base de datos
    r"(\%27|\')\s*UNION\s*select\s*TABLE_NAME,\s*COLUMN_NAME\s*from\s*INFORMATION_SCHEMA.COLUMNS\s*--\s*-", # Busca el patron para obtener nombres de tablas y columnas
    r"(\%27|\')\s*(AND|OR)\s*[\w]+\(\)\s*=\s*\w+",  # Funciones con condiciones
    r"(\%27|\')\s*AND\s*EXIST\s*\(",  # Uso de AND con EXIST
    r"(\%27|\')\s*AND\s*[\w]+\s*IN\s*\(",  # Uso de AND con IN
    r"(\%27|\')\s*AND\s*[\w]+\s*BETWEEN\s+\w+\s+AND\s+\w+",  # Uso de AND con BETWEEN
    r"(\%27|\')\s*SELECT\s*\*",  # Selección de todas las columnas
    r"(\%27|\')\s*DROP\s*TABLE",  # Intento de borrar una tabla
    r"(\%27|\')\s*INSERT\s*INTO",  # Intento de insertar datos
    r"(\%27|\')\s*DELETE\s*FROM",  # Intento de eliminar datos
    r"(\%27|\')\s*UPDATE\s*\w+\s*SET",  # Intento de actualizar datos
    r"(\%27|\')\s*CREATE\s*TABLE",  # Intento de crear una tabla
    r"(\%27|\')\s*EXEC\s*\(",  # Intento de ejecutar un comando
    r"(\%27|\')\s*DECLARE\s*\@",  # Declaración de variables
    r"(\%27|\')\s*CAST\s*\(",  # Uso de CAST
    r"(\%27|\')\s*CONVERT\s*\(",  # Uso de CONVERT
    r"(\%27|\')\s*CHAR\s*\(",  # Uso de CHAR para conversiones
    r"(\%27|\')\s*WAITFOR\s*DELAY\s*'", # Intento de causar un retraso
    r"(\%27|\')",  # Single quote y su versión URL encoded
    r"(\%23|\#)",  # Hash
    #r"(\%2D|\-)",  # Hyphen
    r"--",  # Comentario SQL de una línea
    r"\x27|\x22",  # Single y double quotes en hexadecimal
    r"\x3D%20\x3B|\x3D%20\x27",  # '= ;' y '= '' en hexadecimal
    r"\x27\x4F\x52|\x27\x6F\x72",  # "'OR" en hexadecimal (mayúsculas y minúsculas)
    r"'or%20select\s+\*",  # 'or select * (URL encoded)
    r"admin'--",  # admin'--
    r"'\s*or\s*'\s*=\s*'",  # ' or ''='
    r"'\s*or\s*'x'\s*=\s*'x",  # ' or 'x'='x
    r"\)\s*or\s*\(\s*'x'\s*=\s*'x",  # ') or ('x'='x
    r"\s*or\s*\d\s*=\s*\d",  #  or N=N
    r"\s*or\s*\d\s*=\s*\d\s*--",  #  or N=N --
    r"' or \d=\d or ''='",  # ' or N=N or ''='
    r"\s*or\s*'a'\s*=\s*'a",  #  or 'a'='a
    r"exec\s*(xp|sp)",  # exec xp or sp
    r"\;\s*exec\s*",  # ; exec
    r"UNION\s*(ALL\s*)?SELECT",  # UNION [ALL] SELECT
    r"EXISTS\s*\(",  # EXISTS(
    r"'\s*or\s*exists\s*\(",  # ' or exists(
    r"\s*or\s*\(",  #  or (
    r"select\s+.+from",  # select ... from
    r"insert\s+into",  # insert into
    r"delete\s+from",  # delete from
    r"update\s+\w+\s+set",  # update ... set
    r"create\s+table",  # create table
    r"alter\s+table",  # alter table
    r"drop\s+table",  # drop table
    r"drop\s+database",  # drop database
    r"\|\|UTL_HTTP\.REQUEST",  # ||UTL_HTTP.REQUEST
    r"\;\s*SELECT\s*\*",  # ; SELECT *
    r"to_timestamp_tz",  # to_timestamp_tz
    r"tz_offset",  # tz_offset
    r"\%20or\%201\%3D1",  # %20or%201=1
    r"\%27\%20or\%201\%3D1",  # %27%20or%201=1
    r"\%20'\%73\%6C\%65\%65\%70\%2050'",  # %20'sleep%2050'
    r"\%2A\%7C",  # *|
    r"\%2A\%28\%7C\%28\w+\%3D\%2A\%29\%29",  # *(|(attribute=*)
    r"\(",  # (
    r"\)",  # )
    r"\&",  # &
    r"\!",  # !
    r"'\s*or\s*1\s*=\s*1\s*or\s*''\s*='",  # ' or 1=1 or ''='
    r"'\s*or\s*'\s*=\s*'",  # ' or ''='
    r"'x'\s*or\s*1\s*=\s*1\s*or\s*'x'\s*=\s*'y",  # 'x' or 1=1 or 'x'='y
    r"/\s*/\s*\*",  # //*
    r"\*\/\s*\*"  # */*
]

def burn_baby():
    
    #patron = r'\[src_ip=(?P<src_ip>[^\]]+)\].*request=\["username=(?P<username>[^&]+)&password=(?P<password>[^"\]]+)'
    patron = r'\[src_ip=(?P<src_ip>[^\]]+)\].*payload=\["(?P<payload>[^"]+)"\]'


    # Usar deque para almacenar solo los últimos 5000 registros
    datos_deque = deque(maxlen=500)

    ruta = '/var/log/nginx/hackaton.log'
    # Abrir el archivo de logs y extraer solo los últimos 500 datos
    with open(ruta, 'r', encoding='utf-8') as archivo:
        for linea in archivo:
            coincidencia = re.search(patron, linea)
            if coincidencia:
                # Usar coincidencia.groupdict() para capturar automáticamente todos los grupos nombrados
                datos_deque.append(coincidencia.groupdict())

    # Convertir el deque en un DataFrame de Pandas
    A = pd.DataFrame(datos_deque)
    A.tail()

    unquote_plus('&apos;%20OR')
    A['payload_decodificado'] = A['payload'].apply(lambda x: unquote_plus(x))
    A.tail()

    def evaluar(cadena):
        for patron in patrones_inyeccion_sql:
            if re.search(patron, cadena, re.IGNORECASE):
                return True
        return False  # Mover este retorno fuera del bucle for



    A['inyeccion_payload'] = A['payload_decodificado'].apply(lambda x: evaluar(x))
    A.tail()

    mask = A['inyeccion_payload'] == True
    A = A[mask]
    A.tail()

    return print(A.tail())

#burn_baby(umbral)


while True:
    burn_baby()
    time.sleep(2)


unquote_plus(x)













