import hashlib


# message to be hashed
m = "I hope this hash function work "
m2 = "I hope this hash function works "


# You can pick block length to be whatever you want
def iterative_SHA512_Hash(message, block_length):
    message_at = [] # store the message blocks
    hash_at = [] # store the hash of each block
    size = len(message)

    if size % block_length != 0:
        k = (size / block_length) + 1
    else:
        k = size / block_length

    for pos in range(0, k):
        message_at.append(message[pos:pos + block_length]) # add message into array
        if pos == 0:
            hash_at.append(SHA512(message_at[pos])) # hash the first block
        else:
            hash_at.append(SHA512(hash_at[-1] + message_at[pos])) # add strings together then hash

    for j in range(0, len(hash_at)):
        print hash_at[j]  # print out all hashes

    return hash_at[-1] # return the last hash

def SHA512(x):  # hash function used
    hash_object = hashlib.sha512(x)
    hex_dig = hash_object.hexdigest()
    return str(hex_dig)



print SHA512(m)

# print SHA512(m2) this can be used to help show how hash functions are one way

iterative_SHA512_Hash(m, 15)

"""It should be noted that iterative hashing is not considered more secure than just hashing the entire message"""