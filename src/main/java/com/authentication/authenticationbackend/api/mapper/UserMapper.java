package com.authentication.authenticationbackend.api.mapper;

import com.authentication.authenticationbackend.api.dao.UserDto;
import com.authentication.authenticationbackend.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    UserDto userToUserDto(User user);

}
