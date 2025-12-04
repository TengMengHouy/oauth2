package com.example.security.custom;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.example.domain.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetails implements UserDetails, Serializable {

    private final Long id;
    private final String uuid;
    private final String username;
    private final String email;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String password;
    private final String familyName;
    private final String givenName;
    private final String phoneNumber;
    private final String gender;
    private final LocalDate dob;
    private final String profileImage;
    private final String coverImage;
    private final Boolean accountNonExpired;
    private final Boolean accountNonLocked;
    private final Boolean credentialsNonExpired;
    private final Boolean enabled;
    private final Boolean emailVerified;
    private final Set<GrantedAuthority> authorities;

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.uuid = user.getUuid();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.familyName = user.getFamilyName();
        this.givenName = user.getGivenName();
        this.phoneNumber = user.getPhoneNumber();
        this.gender = user.getGender();
        this.dob = user.getDob();
        this.profileImage = user.getProfileImage();
        this.coverImage = user.getCoverImage();
        this.accountNonExpired = user.getAccountNonExpired();
        this.accountNonLocked = user.getAccountNonLocked();
        this.credentialsNonExpired = user.getCredentialsNonExpired();
        this.enabled = user.getIsEnabled();
        this.emailVerified = user.getEmailVerified();
        this.authorities = user.getAuthorities() == null ? Set.of() :
                user.getAuthorities().stream().map(a -> new SimpleGrantedAuthority(a.getName())).collect(Collectors.toUnmodifiableSet());
    }

    @JsonCreator
    public CustomUserDetails(
            @JsonProperty("id") Long id,
            @JsonProperty("uuid") String uuid,
            @JsonProperty("username") String username,
            @JsonProperty("email") String email,
            @JsonProperty("password") String password,
            @JsonProperty("familyName") String familyName,
            @JsonProperty("givenName") String givenName,
            @JsonProperty("phoneNumber") String phoneNumber,
            @JsonProperty("gender") String gender,
            @JsonProperty("dob") LocalDate dob,
            @JsonProperty("profileImage") String profileImage,
            @JsonProperty("coverImage") String coverImage,
            @JsonProperty("accountNonExpired") Boolean accountNonExpired,
            @JsonProperty("accountNonLocked") Boolean accountNonLocked,
            @JsonProperty("credentialsNonExpired") Boolean credentialsNonExpired,
            @JsonProperty("enabled") Boolean enabled,
            @JsonProperty("emailVerified") Boolean emailVerified,
            @JsonProperty("authorities") Set<String> authorityNames
    ) {
        this.id = id;
        this.uuid = uuid;
        this.username = username;
        this.email = email;
        this.password = password;
        this.familyName = familyName;
        this.givenName = givenName;
        this.phoneNumber = phoneNumber;
        this.gender = gender;
        this.dob = dob;
        this.profileImage = profileImage;
        this.coverImage = coverImage;
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.credentialsNonExpired = credentialsNonExpired;
        this.enabled = enabled;
        this.emailVerified = emailVerified;
        if (authorityNames == null || authorityNames.isEmpty()) {
            this.authorities = Set.of();
        } else {
            this.authorities = authorityNames.stream().filter(Objects::nonNull)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toUnmodifiableSet());
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }

    @Override
    public String getPassword() { return password; }

    @Override
    public String getUsername() { return username; }

    @Override
    public boolean isAccountNonExpired() { return accountNonExpired == null || accountNonExpired; }

    @Override
    public boolean isAccountNonLocked() { return accountNonLocked == null || accountNonLocked; }

    @Override
    public boolean isCredentialsNonExpired() { return credentialsNonExpired == null || credentialsNonExpired; }

    @Override
    public boolean isEnabled() { return enabled == null || enabled; }

    public String getFullName() {
        String g = givenName == null ? "" : givenName.trim();
        String f = familyName == null ? "" : familyName.trim();
        if (g.isEmpty() && f.isEmpty()) return "";
        if (g.isEmpty()) return f;
        if (f.isEmpty()) return g;
        return g + " " + f;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CustomUserDetails)) return false;
        CustomUserDetails that = (CustomUserDetails) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() { return Objects.hash(id); }
}
