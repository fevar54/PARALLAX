# PARALLAX
Regla que busca la presencia de archivos y comportamiento
Esta regla busca la presencia de los archivos payload1.exe y payload2.exe
el proceso legítimo imageres.dll y el proceso inyectado pipanel.exe en las rutas de archivos especificadas. 
Luego, verifica que los archivos payload1.exe y payload2.exe tengan la cabecera MZ y que al menos uno de ellos tenga una cabecera de punto de entrada EP. 
Finalmente, verifica que todos los strings estén presentes y que al menos uno de ellos lo esté en el archivo escaneado. 
Si se cumplen estas condiciones, se considera que la regla ha encontrado una posible instancia de Parallax RAT. 
Sin embargo, es posible que se necesiten ajustes adicionales para adaptar la regla a tus necesidades específicas.
