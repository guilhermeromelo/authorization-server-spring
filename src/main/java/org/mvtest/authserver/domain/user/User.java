package org.mvtest.authserver.domain.user;

import javax.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "users")
public class User {
    @Id
    @SequenceGenerator(name="sgenerator", sequenceName="user_id_seq", allocationSize=1)
    @GeneratedValue(generator="sgenerator", strategy=GenerationType.SEQUENCE)
    private Long id;
    private String nome;
    private String login;
    private String email;
    private String senha;

    public User() { }

    public User(Long id, String name, String login, String email, String senha) {
        this.id = id;
        this.nome = name;
        this.login = login;
        this.email = email;
        this.senha = senha;
    }


    //GETTERS AND SETTERS ------------------------------------------------------------------
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    //ToString, Equals and HashCode ----------------------------------------------------------------------
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + nome + '\'' +
                ", login='" + login + '\'' +
                ", email='" + email + '\'' +
                ", password='" + senha + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id) && Objects.equals(nome, user.nome) &&
                Objects.equals(login, user.login) && Objects.equals(email, user.email) &&
                Objects.equals(senha, user.senha);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, nome, login, email, senha);
    }
}
