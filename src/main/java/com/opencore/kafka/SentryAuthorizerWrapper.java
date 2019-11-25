package com.opencore.kafka;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Acl;
import kafka.security.auth.Authorizer;
import kafka.security.auth.IdempotentWrite;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.TransactionalId;
import kafka.security.auth.Write$;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.sentry.kafka.authorizer.SentryKafkaAuthorizer;
import scala.collection.immutable.Map;
import scala.collection.immutable.Set;

public class SentryAuthorizerWrapper implements Authorizer {

  private Authorizer wrappedAuthorizer = new SentryKafkaAuthorizer();

  @Override
  public boolean authorize(Session session, Operation operation, Resource resource) {

    if (resource.resourceType().toString().equals(TransactionalId.name())) {
      // Transactional IDs are simply omitted when checking ACLs
      // this takes away the possibility to explicitly authorize
      // access to these
      return true;
    } else {
      // Check if this is an idempotent write, if yes, it will be
      // rewritten as a regular write
      if (operation.name().equals(IdempotentWrite.name())) {
        return wrappedAuthorizer.authorize(session, Write$.MODULE$, resource);
      }
    }
    return wrappedAuthorizer.authorize(session, operation, resource);
  }

  @Override
  public void addAcls(Set<Acl> acls, Resource resource) {
    addAcls(acls, resource);
  }

  @Override
  public boolean removeAcls(Set<Acl> acls, Resource resource) {
    return removeAcls(acls, resource);
  }

  @Override
  public boolean removeAcls(Resource resource) {
    return removeAcls(resource);
  }

  @Override
  public Set<Acl> getAcls(Resource resource) {
    return getAcls(resource);
  }

  @Override
  public Map<Resource, Set<Acl>> getAcls(KafkaPrincipal principal) {
    return wrappedAuthorizer.getAcls(principal);
  }

  @Override
  public Map<Resource, Set<Acl>> getAcls() {
    return wrappedAuthorizer.getAcls();
  }

  @Override
  public void close() {
    wrappedAuthorizer.close();
  }

  @Override
  public void configure(java.util.Map<String, ?> map) {
    wrappedAuthorizer.configure(map);
  }
}
