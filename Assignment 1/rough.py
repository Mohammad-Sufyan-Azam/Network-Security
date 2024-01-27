# def order_matrix(key):
#     ''' Returns the list of columns of the matrix in the order specified by the key'''
#     order_indices = []
    
#     for i in key:
#         order_indices.append((int(i), key.index(i)))

#     order_indices.sort()

#     return order_indices

# print(order_matrix("4037"))
# matrix = []
# for i in range(4):
#     matrix.append([])
# print(matrix)

import numpy as np

n = '4037'
s = np.argsort(n)
print(s)

# create a numpy array of size n_rows x n_cols
matrix = np.empty((3, 4), dtype=str)
print(matrix)

c2 = 'abc'
# add c2 to column 2
matrix[:, 2] = list(c2)
print(matrix)