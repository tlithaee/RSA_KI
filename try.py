session_key = '1234567890987654'
    
session_key_chunks = []

for i in range(0, len(session_key), 2):
    session_key_chunks.append(session_key[i] + session_key[i+1])
    
print(session_key_chunks)