import React, { createContext, useEffect, useState,useCallback } from 'react';
import axios from 'axios';
import { useAuth0 } from '@auth0/auth0-react';

const FetchContext = createContext();
const { Provider } = FetchContext;

const FetchProvider = ({ children }) => {
	const [accessToken, setAccessToken] = useState();
	const { getAccessTokenSilently } = useAuth0();

	const getAccessToken = useCallback(async () => {
		try {
			const token = await getAccessTokenSilently();
			setAccessToken(token);
		} catch (err) {
			console.log(err);
		}
	}, [getAccessTokenSilently]);

	useEffect(() => {
		getAccessToken();
	}, [getAccessToken]);

	const authAxios = axios.create({
		baseURL: process.env.REACT_APP_API_URL
	});

	const publicAxios = axios.create({
		baseURL: process.env.REACT_APP_API_URL
	});

	useEffect(() => {
		const getCsrfToken = async () => {
			try {
				const { data } = await publicAxios.get(
					'/csrf-token'
				);
				publicAxios.defaults.headers['X-CSRF-Token'] = data.csrfToken;
				authAxios.defaults.headers['X-CSRF-Token'] = data.csrfToken;
			} catch (err) {
				console.log(err);
			}
		};
		getCsrfToken();
	}, [authAxios, publicAxios]);

	authAxios.interceptors.request.use(
		config => {
			config.headers.Authorization = `Bearer ${accessToken}`;
			return config;
		},
		error => {
			return Promise.reject(error);
		}
	);

	authAxios.interceptors.response.use(
		response => {
			return response;
		},
		error => {
			const code =
				error && error.response ? error.response.status : 0;
			if (code === 401) {
				getAccessToken();
			}
			return Promise.reject(error);
		}
	);

	return (
		<Provider
			value={{
				authAxios,
				publicAxios
			}}
		>
			{children}
		</Provider>
	);
};

export { FetchContext, FetchProvider };
