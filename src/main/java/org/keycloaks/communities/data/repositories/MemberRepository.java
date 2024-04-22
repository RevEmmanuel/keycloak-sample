package org.keycloaks.communities.data.repositories;

import org.keycloaks.communities.data.models.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {


}
