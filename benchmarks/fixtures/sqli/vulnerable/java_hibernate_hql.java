// Fixture: java-hql-concat — Hibernate HQL concatenation + MyBatis ${} injection
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89, CWE-564
// Pattern: String concatenation in session.createQuery(), MyBatis ${} interpolation

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.apache.ibatis.annotations.Select;
import javax.servlet.http.*;
import java.util.List;

public class HibernateController extends HttpServlet {

    private SessionFactory sessionFactory;

    // VULNERABLE: HQL string concatenation
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String username = request.getParameter("username");
        Session session = sessionFactory.openSession();
        // VULNERABLE: HQL concatenation
        List users = session.createQuery(
            "FROM User WHERE username = '" + username + "'"
        ).list();
        session.close();
    }
}

// VULNERABLE: MyBatis ${} interpolation in annotation
interface UserMapper {
    // VULNERABLE: ${tableName} is raw interpolation, #{id} is safe parameterization
    @Select("SELECT * FROM ${tableName} WHERE id = #{id}")
    User findById(String tableName, int id);

    // VULNERABLE: ${orderBy} allows arbitrary SQL in ORDER BY position
    @Select("SELECT * FROM users ORDER BY ${orderBy}")
    List<User> findAllSorted(String orderBy);
}
