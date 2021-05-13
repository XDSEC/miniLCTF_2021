from qiskit import (
    QuantumCircuit, 
    QuantumRegister, 
    ClassicalRegister,
    Aer, 
    assemble,
    execute
)

'''
Allowed operations on medallions:
    1. X gate
    2. Y gate
    3. Z gate
    4. Hadamard gate
    5. Identity gate
    6. Rx gate
    7. Ry gate
    8. Rz gate
    9. CNOT gate
'''
def game(Circuitlist , init_state):
    qr = QuantumRegister(2)
    cr = ClassicalRegister(1)
    qc = QuantumCircuit(qr, cr)
    qc.initialize(init_state, qr)
    for i in Circuitlist:
        if i[0] == 1:
            qc.x(*i[1])
        elif i[0] == 2:
            qc.y(*i[1])
        elif i[0] == 3:
            qc.z(*i[1])
        elif i[0] == 4:
            qc.h(*i[1])
        elif i[0] == 5:
            qc.i(*i[1])
        elif i[0] == 6:
            qc.rx(*i[1])
        elif i[0] == 7:
            qc.ry(*i[1])
        elif i[0] == 8:
            qc.rz(*i[1])
        elif i[0] == 9:
            qc.cx(*i[1])
        else:
            raise ValueError('operation not recognized')
    
    qc.measure(1 , 0)
    sv_sim = Aer.get_backend('statevector_simulator')
    qobj = assemble(qc)
    job = sv_sim.run(qobj)
    measurement_result = job.result().get_counts()
    for i in measurement_result:
        return i

