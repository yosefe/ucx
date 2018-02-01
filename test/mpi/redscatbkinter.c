/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/*
 *  (C) 2011 by Argonne National Laboratory.
 *      See COPYRIGHT in top-level directory.
 */
/*
 * Test of reduce scatter block with large data on an intercommunicator
 * (needed in MPICH to trigger the long-data algorithm)
 *
 * Each processor contributes its rank + the index to the reduction,
 * then receives the ith sum
 *
 * Can be called with any number of processors.
 */

#include "mpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "mpitest.h"


int MTestGetIntercomm2(MPI_Comm * comm, int *isLeftGroup, int min_size)
{
    int size, rank, remsize, merr;
    int done = 0;
    MPI_Comm mcomm = MPI_COMM_NULL;
    MPI_Comm mcomm2 = MPI_COMM_NULL;
    int rleader;

    *comm = MPI_COMM_NULL;
    *isLeftGroup = 0;

    /* Split comm world in half */
    merr = MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if (merr)
        MTestPrintError(merr);
    merr = MPI_Comm_size(MPI_COMM_WORLD, &size);
    if (merr)
        MTestPrintError(merr);
    assert (size > 1);

    merr = MPI_Comm_split(MPI_COMM_WORLD, (rank < size / 2), rank, &mcomm);
    if (merr)
        MTestPrintError(merr);
    if (rank == 0) {
        rleader = size / 2;
    }
    else if (rank == size / 2) {
        rleader = 0;
    }
    else {
        /* Remote leader is signficant only for the processes
         * designated local leaders */
        rleader = -1;
    }
    *isLeftGroup = rank < size / 2;
    merr = MPI_Intercomm_create(mcomm, 0, MPI_COMM_WORLD, rleader, 12345, comm);
    if (merr)
        MTestPrintError(merr);

    merr = MPI_Comm_size(*comm, &size);
    if (merr)
        MTestPrintError(merr);
    merr = MPI_Comm_remote_size(*comm, &remsize);
    if (merr)
        MTestPrintError(merr);
    if (size + remsize >= min_size)
        done = 1;

    /* we are only done if all processes are done */
    MPI_Allreduce(MPI_IN_PLACE, &done, 1, MPI_INT, MPI_LAND, MPI_COMM_WORLD);

    if (!done && *comm != MPI_COMM_NULL) {
        /* avoid leaking communicators */
        merr = MPI_Comm_free(comm);
        if (merr)
            MTestPrintError(merr);
    }

    /* cleanup for common temp objects */
    if (mcomm != MPI_COMM_NULL) {
        merr = MPI_Comm_free(&mcomm);
        if (merr)
            MTestPrintError(merr);
    }
    if (mcomm2 != MPI_COMM_NULL) {
        merr = MPI_Comm_free(&mcomm2);
        if (merr)
            MTestPrintError(merr);
    }

    assert(done);

    return 1;
}

int main(int argc, char **argv)
{
    int err = 0;
    int size, rsize, rank, i, wrank;
    int recvcount,              /* Each process receives this much data */
     sendcount,                 /* Each process contributes this much data */
     basecount;                 /* Unit of elements - basecount *rsize is recvcount,
                                 * etc. */
    int isLeftGroup;
    long long *sendbuf, *recvbuf;
    long long sumval;
    MPI_Comm comm;

    MTest_Init(&argc, &argv);
    comm = MPI_COMM_WORLD;

    basecount = 1024;

    MPI_Comm_rank(MPI_COMM_WORLD, &wrank);
    if (wrank == 0) {
        printf("starting\n");
    }

    MTestGetIntercomm (&comm, &isLeftGroup, 2);

    assert(comm != MPI_COMM_NULL);

    MPI_Comm_remote_size(comm, &rsize);
    MPI_Comm_size(comm, &size);
    MPI_Comm_rank(comm, &rank);

    if (0) {
        printf("[%d] %s (%d,%d) remote %d\n", rank, isLeftGroup ? "L" : "R", rank, size, rsize);
    }

    recvcount = basecount * rsize;
    sendcount = basecount * rsize * size;

    sendbuf = (long long *) malloc(sendcount * sizeof(long long));
    if (!sendbuf) {
        fprintf(stderr, "Could not allocate %d ints for sendbuf\n", sendcount);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    for (i = 0; i < sendcount; i++) {
        sendbuf[i] = (long long) (rank * sendcount + i);
    }
    recvbuf = (long long *) malloc(recvcount * sizeof(long long));
    if (!recvbuf) {
        fprintf(stderr, "Could not allocate %d ints for recvbuf\n", recvcount);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    for (i = 0; i < recvcount; i++) {
        recvbuf[i] = (long long) (-i);
    }

    if (wrank == 0) {
         printf("running2\n");
     }

    MPI_Reduce_scatter_block(sendbuf, recvbuf, recvcount, MPI_LONG_LONG, MPI_SUM, comm);

//    if (wrank == 0)
    {
        printf("checking\n");
    }

    /* Check received data */
    for (i = 0; i < recvcount; i++) {
        sumval = (long long) (sendcount) * (long long) ((rsize * (rsize - 1)) / 2) +
            (long long) (i + rank * rsize * basecount) * (long long) rsize;
        if (recvbuf[i] != sumval) {
            err++;
            if (err < 4) {
                fprintf(stdout, "Did not get expected value for reduce scatter\n");
                fprintf(stdout, "[%d] %s recvbuf[%d] = %lld, expected %lld\n",
                        rank, isLeftGroup ? "L" : "R", i, recvbuf[i], sumval);
            }
        }
    }

    free(sendbuf);
    free(recvbuf);

    MTestFreeComm(&comm);

    MTest_Finalize(err);

    MPI_Finalize();

    return 0;
}
