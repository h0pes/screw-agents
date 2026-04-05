// Fixture: java-stmt-concat — JDBC Statement with concatenation
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89
// Pattern: String concatenation in Statement.executeQuery() and false parameterization

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {

    // VULNERABLE: Statement with string concatenation
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        Statement stmt = conn.createStatement();
        // VULNERABLE: direct concatenation
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE id = " + userId
        );
        // ... process results
        conn.close();
    }

    // VULNERABLE: False parameterization — looks safe but isn't
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String name = request.getParameter("name");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        // VULNERABLE: SQL built via concatenation BEFORE PreparedStatement
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        PreparedStatement ps = conn.prepareStatement(query);  // No bind variables!
        ResultSet rs = ps.executeQuery();
        // ... process results
        conn.close();
    }
}
