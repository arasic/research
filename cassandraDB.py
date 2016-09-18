#!/usr/bin/env python
from cassandra.cluster import Cluster
from cassandra.policies import HostDistance
import datetime
from time import sleep
from cassandra.query import BatchStatement, BatchType, SimpleStatement


class CassandraDB:
    cluster = Cluster(['192.168.2.4'])
    session = None
    def __init__(self, nodeIP):
        self.cluster = Cluster([nodeIP])
        self.session = self.cluster.connect()

    def query(self, lstQueries):
        print "Executing %d queries " % len(lstQueries)
#        self.session = None
        try:
#            import pdb;pdb.set_trace()
#            self.session = self.cluster.connect()
            batch = BatchStatement(BatchType.LOGGED)
            for q in lstQueries:
                batch.add(SimpleStatement(q))

            self.session.execute(batch)
#            results = self.session.execute("select * from test.traffic")
#            for row in results:
#                print row
        except Exception, err:
            print 'An exception has occurred.'
            print Exception, err
            raise IOError('Could not store data')

    def shutdownSession(self):
        if self.session and not self.session.is_shutdown:
            self.session.shutdown()

