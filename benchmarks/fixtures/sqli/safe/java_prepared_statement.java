// Fixture: Safe parameterized queries — Java
// Expected: TRUE NEGATIVE (must NOT be flagged)
// Pattern: Proper PreparedStatement, Hibernate named params, MyBatis #{}, Spring JdbcTemplate

import java.sql.*;
import javax.servlet.http.*;
import org.hibernate.Session;
import org.springframework.jdbc.core.JdbcTemplate;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public class SafeUserController extends HttpServlet {

    // SAFE: PreparedStatement with bind variables
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM users WHERE id = ? AND active = ?");
        pstmt.setString(1, userId);
        pstmt.setBoolean(2, true);
        ResultSet rs = pstmt.executeQuery();
        // ... process results
        conn.close();
    }

    // SAFE: Hibernate named parameters
    public List getUsers(Session session, String username) {
        return session.createQuery("FROM User WHERE username = :name")
            .setParameter("name", username)
            .list();
    }

    // SAFE: Spring JdbcTemplate with placeholders
    public Object getUserSpring(JdbcTemplate jdbc, String id) {
        return jdbc.queryForObject(
            "SELECT * FROM users WHERE id = ?",
            new Object[]{id},
            (rs, rowNum) -> rs.getString("name")
        );
    }
}

// SAFE: MyBatis #{} parameterization
interface SafeUserMapper {
    // #{} is parameterized — values are bound, not interpolated
    @Select("SELECT * FROM users WHERE id = #{id}")
    Object findById(int id);

    @Select("SELECT * FROM users WHERE name = #{name} ORDER BY created_at")
    List<Object> findByName(String name);
}
